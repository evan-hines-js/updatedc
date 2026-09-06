use std::io;

use updated::bundle::{read_active, write_active, ReleaseId};
use updated::config::Paths;
use updated::install::InstallTransaction;
use updated::reject::Rejections;
use updated::state::{
    try_read_installed, write_installed, Installed, InstalledState, RepositoryLineage,
};
use updated::transaction::Transaction;

/// The agent's one durable-state boundary.
///
/// This is a final facade, not a trait: the operations that enforce activation ordering, journal
/// history and rejection settlement cannot be overridden by a new backend. File and test-memory
/// storage differ only behind the private primitive methods below; every caller crosses the same
/// invariant-bearing implementation.
pub(crate) struct Store {
    backend: Backend,
}

enum Backend {
    File {
        paths: Box<Paths>,
        rejected: Rejections,
    },
    #[cfg(test)]
    Memory(Box<MemoryBackend>),
}

#[derive(Clone, Copy)]
enum JournalKind {
    Update,
    Install,
}

impl JournalKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Install => "first-install",
        }
    }
}

impl Store {
    pub(crate) fn open(paths: Paths) -> io::Result<Self> {
        std::fs::create_dir_all(&paths.versions)?;
        std::fs::create_dir_all(&paths.staging)?;
        std::fs::create_dir_all(&paths.state_dir)?;
        let rejected = Rejections::load(&paths.rejected)?;
        Ok(Self {
            backend: Backend::File {
                paths: Box::new(paths),
                rejected,
            },
        })
    }

    /// Read the installed record without erasing the distinction between corrupt content and an
    /// I/O failure. In particular, Windows may briefly deny a read while another process still
    /// holds a sharing-incompatible handle; callers must pass that error to the node-local retry
    /// policy rather than silently treating a valid record as corrupt.
    pub(crate) fn installed(&self) -> io::Result<Installed> {
        match &self.backend {
            Backend::File { paths, .. } => try_read_installed(&paths.installed),
            #[cfg(test)]
            Backend::Memory(memory) => Ok(match &memory.installed {
                Some(state) if state.validate().is_ok() => {
                    Installed::Present(Box::new(state.clone()))
                }
                Some(_) => Installed::Invalid,
                None => Installed::Missing,
            }),
        }
    }

    pub(crate) fn journal(&self) -> io::Result<Option<Transaction>> {
        match &self.backend {
            Backend::File { paths, .. } => updated::journal::read(&paths.journal),
            #[cfg(test)]
            Backend::Memory(memory) => {
                if let Some(transaction) = &memory.journal {
                    transaction.validate()?;
                }
                Ok(memory.journal.clone())
            }
        }
    }

    pub(crate) fn install_journal(&self) -> io::Result<Option<InstallTransaction>> {
        match &self.backend {
            Backend::File { paths, .. } => updated::journal::read(&paths.install_journal),
            #[cfg(test)]
            Backend::Memory(memory) => {
                if let Some(transaction) = &memory.install_journal {
                    transaction.validate()?;
                }
                Ok(memory.install_journal.clone())
            }
        }
    }

    pub(crate) fn active_release(&self) -> io::Result<Option<ReleaseId>> {
        match &self.backend {
            Backend::File { paths, .. } => read_active(&paths.active_release),
            #[cfg(test)]
            Backend::Memory(memory) => {
                if let Some(release) = &memory.active {
                    release.validate()?;
                }
                Ok(memory.active.clone())
            }
        }
    }

    pub(crate) fn is_rejected(&self, lineage: &RepositoryLineage, digest: &str) -> bool {
        let Ok(key) = Self::rejection_key(lineage, digest) else {
            // Selection predicates are boolean, so malformed artifact identity has no separate
            // error channel. Treat it as ineligible rather than letting a value the durable
            // rejection store cannot even name pass the never-retry gate.
            return true;
        };
        match &self.backend {
            Backend::File { rejected, .. } => rejected.is_rejected(&key),
            #[cfg(test)]
            Backend::Memory(memory) => memory.rejected.contains(&key),
        }
    }

    fn rejection_is_durable(&self, lineage: &RepositoryLineage, digest: &str) -> bool {
        let Ok(key) = Self::rejection_key(lineage, digest) else {
            return false;
        };
        match &self.backend {
            Backend::File { rejected, .. } => rejected.is_durably_rejected(&key),
            #[cfg(test)]
            Backend::Memory(memory) => !memory.rejections_dirty && memory.rejected.contains(&key),
        }
    }

    /// Whether any durable verdict excludes this exact deployed unit.
    ///
    /// Malformed archive bytes and runtime failures use distinct rejection domains for the same
    /// signed package. Every selector, diagnostic, heartbeat, and fallback gate asks this method
    /// so those identities cannot drift into different never-retry rules.
    pub(crate) fn rejects_deployment(
        &self,
        lineage: &RepositoryLineage,
        application_sha256: &str,
    ) -> bool {
        self.is_rejected(lineage, application_sha256)
            || updated_contracts::digest::deployment_rejection_sha256(application_sha256)
                .is_none_or(|digest| self.is_rejected(lineage, &digest))
    }

    /// Persist runtime evidence against the exact signed package that failed.
    /// Structurally invalid archives still use [`Store::reject_artifact`] directly.
    pub(crate) fn reject_deployment(
        &mut self,
        lineage: &RepositoryLineage,
        application_sha256: &str,
    ) -> io::Result<()> {
        let digest = updated_contracts::digest::deployment_rejection_sha256(application_sha256)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot reject a deployment with an invalid artifact identity",
                )
            })?;
        self.record_rejection(lineage, &digest)
    }

    /// Commit installed metadata only for the release this machine is actually pointing at.
    ///
    /// Activation and commit are intentionally separate crash barriers: an update must run the
    /// candidate's converge and health gate after moving the pointer but before making it the
    /// installed head. Keeping the ordering check here gives that protocol one enforceable shape:
    /// verify/activate first, then commit. Metadata-only changes (confirmation and repository
    /// rebinds) pass through the same gate because they retain the active release identity.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
        state.validate()?;
        match self.active_release()? {
            Some(active) if active == state.release => {}
            Some(active) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to commit installed release {} while active release is {}",
                        state.release.version, active.version
                    ),
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to commit installed release {} without an active release",
                        state.release.version
                    ),
                ));
            }
        }
        self.validate_installed_transition(state)?;
        match &mut self.backend {
            Backend::File { paths, .. } => write_installed(&paths.installed, state),
            #[cfg(test)]
            Backend::Memory(memory) => {
                memory.installed = Some(state.clone());
                Ok(())
            }
        }
    }

    /// Promote the active provisional head through the same checked read and commit grammar as
    /// every other installed-state mutation. Keeping the read inside this operation prevents a
    /// caller from observing `Invalid` on a transient Windows sharing fault and silently skipping
    /// confirmation before the retry boundary is reached.
    pub(crate) fn prove_provisional(&mut self) -> io::Result<bool> {
        let mut state = match self.installed()? {
            Installed::Present(state) => state,
            Installed::Missing => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "cannot confirm a missing installed state",
                ));
            }
            Installed::Invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot confirm a corrupt installed state",
                ));
            }
        };
        if !state.prove_provisional() {
            return Ok(false);
        }
        self.commit_installed(&state)?;
        Ok(true)
    }

    /// Enforce the complete installed-record transition grammar at the durable write boundary.
    ///
    /// Checking only that the active pointer named `state.release` left a second update path: any
    /// caller could activate a new release and overwrite the record without an update journal or
    /// rollback intent. Repair did exactly that when an assignment moved. The record may now be
    /// created only from first-install intent, change executable identity only under update or
    /// rollback evidence, or perform one of the three metadata-only transitions below.
    fn validate_installed_transition(&self, next: &InstalledState) -> io::Result<()> {
        match self.installed()? {
            Installed::Missing if self.install_commit_is_authorized(next)? => Ok(()),
            Installed::Missing => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to create installed state without matching first-install intent",
            )),
            Installed::Invalid => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "refusing to overwrite corrupt installed state",
            )),
            Installed::Present(current)
                if Self::metadata_transition_is_authorized(&current, next)
                    || self.pending_rollback_is_authorized(&current, next)
                    || self.journal_transition_is_authorized(&current, next)? =>
            {
                Ok(())
            }
            Installed::Present(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing an installed-state transition without matching durable intent",
            )),
        }
    }

    fn install_commit_is_authorized(&self, next: &InstalledState) -> io::Result<bool> {
        let Some(tx) = self.install_journal()? else {
            return Ok(false);
        };
        Ok(matches!(
            tx.phase,
            updated::install::InstallPhase::Placed | updated::install::InstallPhase::Committed
        ) && tx.matches_installed(next)
            && next.rollback_guard.is_none()
            && !next.is_proven())
    }

    /// The only journal-free rewrites of an existing record: exact replay, a lineage-only rebind,
    /// provisional confirmation, or pending settlement. Exactly one metadata fact may change so a
    /// new call site cannot accidentally combine transitions across a crash barrier.
    fn metadata_transition_is_authorized(current: &InstalledState, next: &InstalledState) -> bool {
        if current == next {
            return true;
        }
        if current.release != next.release
            || current.archive_sha256 != next.archive_sha256
            || current.reconciler != next.reconciler
        {
            return false;
        }

        let lineage_changed = current.repository_lineage != next.repository_lineage;
        let pending_changed = current.rollback_guard != next.rollback_guard;
        let confirmed_changed = current.is_proven() != next.is_proven();
        match (lineage_changed, pending_changed, confirmed_changed) {
            // Authenticated rebind. Lifecycle state is carried verbatim.
            (true, false, false) => true,
            // A first successful gate confirms a provisional install.
            (false, false, true) => {
                !current.is_proven() && next.is_proven() && current.rollback_guard.is_none()
            }
            // The confirmation window settles an update by dropping only its rollback intent.
            (false, true, false) => {
                current.rollback_guard.is_some() && next.rollback_guard.is_none()
            }
            _ => false,
        }
    }

    /// A pending record is itself durable authority to finish the rollback it names, including the
    /// crash boundary where the active pointer already moved but no update journal remains.
    fn pending_rollback_is_authorized(
        &self,
        current: &InstalledState,
        next: &InstalledState,
    ) -> bool {
        let Some(pending) = &current.rollback_guard else {
            return false;
        };
        // With no update journal left, `pending` is the only durable rollback authority. Do not
        // erase it until the candidate verdict it names has reached the rejection store; otherwise
        // committing the predecessor would destroy the last identity of the bytes that must never
        // be retried.
        self.rejection_is_durable(
            &current.repository_lineage,
            &pending.candidate_rejection_sha256,
        ) && next.repository_lineage == pending.previous_repository_lineage
            && next.release == pending.previous_release
            && next.archive_sha256 == pending.previous_archive_sha256
            && next.reconciler == pending.reconciler
            && next.rollback_guard.is_none()
            && next.is_proven()
    }

    fn journal_transition_is_authorized(
        &self,
        current: &InstalledState,
        next: &InstalledState,
    ) -> io::Result<bool> {
        let Some(tx) = self.journal()? else {
            return Ok(false);
        };

        let current_is_predecessor = tx.matches_previous(current);
        let next_is_candidate = tx.matches_candidate(next);
        let pending_binds_transaction = next
            .rollback_guard
            .as_ref()
            .is_some_and(|guard| tx.matches_rollback_guard(guard));
        if matches!(
            tx.phase,
            updated::transaction::Phase::Converged | updated::transaction::Phase::Verified
        ) && !tx.candidate_rejection_required
            && current_is_predecessor
            && next_is_candidate
            && pending_binds_transaction
            && next.is_proven()
        {
            return Ok(true);
        }

        let current_is_candidate = tx.matches_candidate(current);
        let next_is_predecessor = tx.matches_previous(next) && next.rollback_guard.is_none();
        Ok(tx.phase == updated::transaction::Phase::RolledBack
            && current_is_candidate
            && next_is_predecessor
            && (next.is_proven()
                || self.rejects_deployment(
                    &tx.previous_repository_lineage,
                    &tx.previous_archive_sha256,
                )))
    }

    /// Write the journal bytes, unconditionally. The implementation detail behind
    /// [`Store::write_journal`] — call that instead: it is the one place the replace rule is
    /// enforced, and a direct `record_journal` can silently bury another transaction's
    /// compensation obligation.
    #[allow(clippy::disallowed_methods)]
    fn record_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        match &mut self.backend {
            Backend::File { paths, .. } => updated::journal::write(&paths.journal, tx),
            #[cfg(test)]
            Backend::Memory(memory) => {
                memory.journal = Some(tx.clone());
                Ok(())
            }
        }
    }

    /// Remove the journal file, unconditionally. The implementation detail behind
    /// [`Store::clear_journal`] — call that instead: it is the one place the discard rule is
    /// enforced, and a direct `remove_journal` bypasses the machine's compensation guarantee.
    #[allow(clippy::disallowed_methods)]
    fn remove_journal(&mut self) -> io::Result<()> {
        match &mut self.backend {
            Backend::File { paths, .. } => updated::journal::clear(&paths.journal),
            #[cfg(test)]
            Backend::Memory(memory) => {
                memory.journal = None;
                Ok(())
            }
        }
    }

    /// Write first-install journal bytes unconditionally. The implementation detail behind
    /// [`Store::write_install_journal`].
    #[allow(clippy::disallowed_methods)]
    fn record_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        match &mut self.backend {
            Backend::File { paths, .. } => updated::journal::write(&paths.install_journal, tx),
            #[cfg(test)]
            Backend::Memory(memory) => {
                memory.install_journal = Some(tx.clone());
                Ok(())
            }
        }
    }

    /// Remove first-install journal bytes unconditionally. The implementation detail behind
    /// [`Store::clear_install_journal`].
    #[allow(clippy::disallowed_methods)]
    fn remove_install_journal(&mut self) -> io::Result<()> {
        match &mut self.backend {
            Backend::File { paths, .. } => updated::journal::clear(&paths.install_journal),
            #[cfg(test)]
            Backend::Memory(memory) => {
                memory.install_journal = None;
                Ok(())
            }
        }
    }

    /// Persist content evidence against one structurally invalid artifact.
    ///
    /// Runtime failures must use [`Store::reject_deployment`], whose identity distinguishes
    /// execution evidence from a malformed archive. Keeping the generic
    /// ledger writer private makes that evidence distinction explicit at every production call
    /// site instead of relying on callers to pass the right kind of digest.
    pub(crate) fn reject_artifact(
        &mut self,
        lineage: &RepositoryLineage,
        digest: &str,
    ) -> io::Result<()> {
        self.record_rejection(lineage, digest)
    }

    fn record_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        let key = Self::rejection_key(lineage, digest)?;
        match &mut self.backend {
            Backend::File { rejected, .. } => rejected.reject(&key),
            #[cfg(test)]
            Backend::Memory(memory) => {
                // Match `Rejections::reject`: once bad-byte evidence is observed, a persistence
                // failure cannot make it eligible again in the live process. The returned error
                // still tells the state machine to retain and replay its durable obligation.
                memory.rejected.insert(key);
                memory.rejections_dirty = memory.fail_reject;
                if memory.fail_reject {
                    return Err(io::Error::other("injected rejection write failure"));
                }
                Ok(())
            }
        }
    }

    fn rejection_key(lineage: &RepositoryLineage, digest: &str) -> io::Result<String> {
        if !lineage.validate() || !updated_contracts::is_canonical_sha256(digest) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a rejection requires a canonical repository lineage and digest",
            ));
        }
        Ok(lineage.rejection_key(digest))
    }

    /// Re-hash the exact bytes a pointer is about to name. Ingest verifies a release once, but
    /// activation runs again on paths that never re-checked *these* bytes (a crash-recovered
    /// rollback activates the PREDECESSOR; drift restore re-points at the committed release), so
    /// predecessor bytes are never launched unverified even for one boot. A failure here means this
    /// node cannot currently prove its materialized tree intact. It is storage/integrity evidence,
    /// never a verdict on the authenticated archive, so callers retry or recover without rejecting
    /// the release.
    fn verify_release(&self, release: &ReleaseId) -> io::Result<()> {
        release.validate()?;
        match &self.backend {
            Backend::File { paths, .. } => {
                updated::bundle::verify_release(&paths.versions, release)
            }
            #[cfg(test)]
            Backend::Memory(memory) => {
                if memory.fail_verify_release {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "injected release verification failure",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Move the durable active-release pointer to `release` WITHOUT re-verifying. A failure is pure
    /// infrastructure (ENOSPC, transient I/O on the atomic write), never the release's fault, so
    /// callers recover rather than permanently reject a healthy release.
    #[allow(clippy::disallowed_methods)]
    fn point_active(&mut self, release: &ReleaseId) -> io::Result<()> {
        match &mut self.backend {
            Backend::File { paths, .. } => write_active(&paths.active_release, release),
            #[cfg(test)]
            Backend::Memory(memory) => {
                if memory.fail_point_active {
                    return Err(io::Error::other("injected active-pointer write failure"));
                }
                memory.active = Some(release.clone());
                Ok(())
            }
        }
    }

    /// Verify then point — the sole activation path. Both failures are node-local I/O: staging has
    /// already classified every reproducible archive fault before publishing this tree, while this
    /// re-check detects later local drift. Keeping one ordinary error path makes it impossible for a
    /// caller to reinterpret either failure as permanent release evidence.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn activate(&mut self, release: &ReleaseId) -> io::Result<()> {
        self.verify_release(release)?;
        self.point_active(release)
    }
    /// Destroy the journal — but only when its transaction no longer owes the machine anything.
    /// Phase is not proof: `Committed` and `RolledBack` are writable bytes too. The one discard
    /// predicate below requires the matching active pointer, the complete deployed-unit record,
    /// and any required rejection before either deletion or replacement may erase the journal.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn clear_journal(&mut self) -> io::Result<()> {
        if let Some(tx) = self.journal()? {
            if !self.journal_may_discard(&tx)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to discard a journal at {:?}: the transaction still owes a \
                         commit or a settled rollback",
                        tx.phase
                    ),
                ));
            }
        }
        self.remove_journal()
    }

    /// The single evidence rule for every operation that would erase a transaction, whether by
    /// deleting its file or overwriting it with another id.
    fn journal_may_discard(&self, tx: &Transaction) -> io::Result<bool> {
        if tx.candidate_rejection_required
            && !self.rejection_is_durable(
                &tx.candidate_repository_lineage,
                &tx.candidate_rejection_sha256,
            )
        {
            return Ok(false);
        }
        if tx.phase == updated::transaction::Phase::Prepared {
            return Ok(true);
        }
        let active = self.active_release()?;
        let Installed::Present(installed) = self.installed()? else {
            return Ok(false);
        };
        Ok(match tx.phase {
            updated::transaction::Phase::Converged
            | updated::transaction::Phase::Verified
            | updated::transaction::Phase::Committed => {
                self.forward_commit_is_durable(tx, &installed)
            }
            updated::transaction::Phase::RolledBack => {
                active.as_ref() == Some(&tx.previous_release) && tx.matches_previous(&installed)
            }
            updated::transaction::Phase::Prepared
            | updated::transaction::Phase::Activated
            | updated::transaction::Phase::RollbackPlanned
            | updated::transaction::Phase::CandidateCompensated
            | updated::transaction::Phase::Restored
            | updated::transaction::Phase::RollbackVerified => false,
        })
    }
    /// Persist a transaction without rewriting its identity or its durable history. Until a
    /// transaction settles, a same-id record must be one exact successor; a different id may
    /// replace it only while nothing has been displaced. Burying unsettled evidence is the same
    /// destruction [`Store::clear_journal`] refuses, through a different door.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        tx.validate()?;
        self.ensure_exclusive_journal(JournalKind::Update)?;
        if tx.phase == updated::transaction::Phase::Committed
            && !self.forward_commit_is_authorized(tx)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to record a committed transaction before its exact deployed unit and rollback intent are durable",
            ));
        }
        if let Some(existing) = self.journal()? {
            if existing.id != tx.id && !self.journal_may_discard(&existing)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to bury the journal of transaction {} at {:?} under \
                         transaction {}: the existing transaction still owes a commit or a \
                         settled rollback",
                        existing.id, existing.phase, tx.id
                    ),
                ));
            }
            if existing.id != tx.id && !self.journal_start_is_authorized(tx)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to start transaction {} at {:?} without initial intent",
                        tx.id, tx.phase
                    ),
                ));
            }
            if existing.id == tx.id && !existing.permits_replacement(tx) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing an invalid rewrite of transaction {} from {:?} to {:?}",
                        existing.id, existing.phase, tx.phase
                    ),
                ));
            }
            if existing.id == tx.id
                && existing.phase == updated::transaction::Phase::Committed
                && tx.phase == updated::transaction::Phase::RollbackPlanned
                && !self.pending_authorizes_rollback_journal(tx)?
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "refusing to restart a committed transaction without matching pending rollback intent",
                ));
            }
        } else if !self.journal_start_is_authorized(tx)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to start transaction {} at {:?} without initial intent",
                    tx.id, tx.phase
                ),
            ));
        }
        self.record_journal(tx)
    }

    fn forward_commit_is_authorized(&self, tx: &Transaction) -> io::Result<bool> {
        let Installed::Present(installed) = self.installed()? else {
            return Ok(false);
        };
        Ok(
            self.active_release()?.as_ref() == Some(&tx.candidate_release)
                && self.forward_commit_is_durable(tx, &installed),
        )
    }

    /// The exact point where the journal's forward obligation has transferred to the atomic
    /// installed record. Once both the candidate and its rollback intent match, `pending` is the
    /// durable authority even if a later boot has already moved the active pointer back to the
    /// predecessor. Every journal-destruction path and the terminal-write gate share this rule.
    fn forward_commit_is_durable(&self, tx: &Transaction, installed: &InstalledState) -> bool {
        !tx.candidate_rejection_required
            && tx.matches_candidate(installed)
            && installed
                .rollback_guard
                .as_ref()
                .is_some_and(|guard| tx.matches_rollback_guard(guard))
    }

    fn journal_start_is_authorized(&self, tx: &Transaction) -> io::Result<bool> {
        if self.pending_authorizes_rollback_journal(tx)? {
            return Ok(true);
        }
        let Installed::Present(installed) = self.installed()? else {
            return Ok(false);
        };
        Ok(tx.phase == updated::transaction::Phase::Prepared
            && !tx.candidate_rejection_required
            && tx.rollback_health_failures == 0
            && installed.is_proven()
            && installed.rollback_guard.is_none()
            && tx.matches_previous(&installed)
            && self.active_release()?.as_ref() == Some(&installed.release))
    }

    /// The one non-Prepared journal start: materializing rollback intent already carried by the
    /// atomic installed record. Every identity is copied from that record, so a caller cannot use
    /// this exception to manufacture a different predecessor or candidate.
    fn pending_authorizes_rollback_journal(&self, tx: &Transaction) -> io::Result<bool> {
        let Installed::Present(installed) = self.installed()? else {
            return Ok(false);
        };
        let Some(pending) = &installed.rollback_guard else {
            return Ok(false);
        };
        Ok(tx.phase == updated::transaction::Phase::RollbackPlanned
            && tx.rollback_health_failures == 0
            && tx.matches_rollback_guard(pending)
            && tx.matches_candidate(&installed))
    }
    /// Persist first-install intent without ever burying a different interrupted install. An
    /// install has no abort path: every non-committed record is resumed, and a committed record is
    /// cleared before a later install can begin. Replays and phase advances of the same attempt are
    /// the only legitimate replacement.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        tx.validate()?;
        self.ensure_exclusive_journal(JournalKind::Install)?;
        if !self.install_phase_is_authorized(tx)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to record first-install phase {:?} before its machine barrier is durable",
                    tx.phase
                ),
            ));
        }
        if let Some(existing) = self.install_journal()? {
            if existing.id != tx.id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to bury first-install transaction {} at {:?} under transaction {}",
                        existing.id, existing.phase, tx.id
                    ),
                ));
            }
            if !existing.permits_replacement(tx) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing an invalid rewrite of first-install transaction {} from {:?} to {:?}",
                        existing.id, existing.phase, tx.phase
                    ),
                ));
            }
        } else if !self.install_start_is_authorized(tx)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to start first-install transaction {} at {:?}",
                    tx.id, tx.phase
                ),
            ));
        }
        self.record_install_journal(tx)
    }

    /// First installation starts only on an empty managed installation. Failed provisional
    /// installs retain their evidence and require recovery; rejection never grants reinstall.
    fn install_start_is_authorized(&self, tx: &InstallTransaction) -> io::Result<bool> {
        if tx.phase != updated::install::InstallPhase::Started
            || self.rejects_deployment(&tx.repository_lineage, &tx.archive_sha256)
        {
            return Ok(false);
        }
        let active = self.active_release()?;
        Ok(match self.installed()? {
            Installed::Missing => active.is_none(),
            Installed::Present(_) | Installed::Invalid => false,
        })
    }

    /// Update and first-install are mutually exclusive durable state machines. Enforce that fact
    /// at both write boundaries, including same-transaction recovery replays: relying on callers
    /// to start them in the right order would leave corrupt or manually seeded state able to make
    /// both machines authoritative at once.
    fn ensure_exclusive_journal(&self, writing: JournalKind) -> io::Result<()> {
        let conflict = match writing {
            JournalKind::Update => self
                .install_journal()?
                .map(|tx| (JournalKind::Install, tx.id)),
            JournalKind::Install => self.journal()?.map(|tx| (JournalKind::Update, tx.id)),
        };
        let Some((existing, id)) = conflict else {
            return Ok(());
        };
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to write {} journal while {} transaction {id} is durable",
                writing.name(),
                existing.name()
            ),
        ))
    }

    /// Machine evidence behind the first-install barriers the store can observe. `Prepared`
    /// follows content verification outside this facade; `Placed` requires the active pointer;
    /// `Committed` additionally requires the complete deployed unit. Recovery may still read an
    /// inconsistent record and repair it, but no ordinary writer can manufacture one.
    fn install_phase_is_authorized(&self, tx: &InstallTransaction) -> io::Result<bool> {
        match tx.phase {
            updated::install::InstallPhase::Started | updated::install::InstallPhase::Prepared => {
                Ok(true)
            }
            updated::install::InstallPhase::Placed => {
                Ok(self.active_release()?.as_ref() == Some(&tx.release))
            }
            updated::install::InstallPhase::Committed => {
                let Installed::Present(installed) = self.installed()? else {
                    return Ok(false);
                };
                Ok(self.active_release()?.as_ref() == Some(&tx.release)
                    && tx.matches_installed(&installed))
            }
        }
    }
    /// Destroy first-install intent only after the authoritative installed record proves the exact
    /// release committed. Phase alone is insufficient: preserving the journal when installed
    /// state is missing or corrupt is what keeps an interrupted enrollment recoverable.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn clear_install_journal(&mut self) -> io::Result<()> {
        if let Some(tx) = self.install_journal()? {
            let installed = match self.installed()? {
                Installed::Present(state) => Some(state),
                Installed::Missing | Installed::Invalid => None,
            };
            if !matches!(
                updated::install::classify_install_recovery(&tx, installed.as_deref()),
                updated::install::InstallRecovery::Committed
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to discard first-install transaction {} at {:?}: its exact deployed unit is not committed",
                        tx.id, tx.phase
                    ),
                ));
            }
        }
        self.remove_install_journal()
    }
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn memory(backend: MemoryBackend) -> Self {
        Self {
            backend: Backend::Memory(Box::new(backend)),
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn memory_backend(&self) -> &MemoryBackend {
        let Backend::Memory(memory) = &self.backend else {
            panic!("the store does not use the test-memory backend");
        };
        memory
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn memory_backend_mut(&mut self) -> &mut MemoryBackend {
        let Backend::Memory(memory) = &mut self.backend else {
            panic!("the store does not use the test-memory backend");
        };
        memory
    }
}

/// Test-only durable bytes behind the same final [`Store`] facade production uses.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryBackend {
    pub(crate) installed: Option<InstalledState>,
    pub(crate) journal: Option<Transaction>,
    pub(crate) install_journal: Option<InstallTransaction>,
    pub(crate) active: Option<ReleaseId>,
    pub(crate) rejected: std::collections::HashSet<String>,
    /// Simulate a state directory that has gone unwritable (ENOSPC, a read-only remount).
    pub(crate) fail_reject: bool,
    pub(crate) rejections_dirty: bool,
    /// Simulate corrupt immutable release bytes at the activation gate.
    pub(crate) fail_verify_release: bool,
    /// Simulate platform I/O failing after verification but before the pointer moves.
    pub(crate) fail_point_active: bool,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl Default for Store {
    fn default() -> Self {
        Self::memory(MemoryBackend::default())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use updated::install::InstallPhase;
    use updated::state::ReconcilerRelease;

    fn install_transaction(id_byte: char, phase: InstallPhase) -> InstallTransaction {
        let release = ReleaseId {
            version: "1.0.0".into(),
            manifest_sha256: "a".repeat(64),
        };
        InstallTransaction {
            id: id_byte.to_string().repeat(64),
            release: release.clone(),
            archive_sha256: "b".repeat(64),
            repository_lineage: RepositoryLineage::from_metadata_url(
                "https://repo.example/metadata/",
            )
            .expect("fixture metadata URL is valid"),
            reconciler: Box::new(ReconcilerRelease {
                definition_sha256: "c".repeat(64),
                product: "reconciler".into(),
                api: 1,
                timeout_millis: 1_000,
            }),
            phase,
        }
    }

    fn update_transaction() -> Transaction {
        let candidate = install_transaction('3', InstallPhase::Started);
        let candidate_rejection_sha256 =
            updated_contracts::digest::deployment_rejection_sha256(&candidate.archive_sha256)
                .expect("fixture artifact identities are canonical");
        Transaction {
            id: "4".repeat(64),
            previous_release: ReleaseId {
                version: "0.9.0".into(),
                manifest_sha256: "e".repeat(64),
            },
            previous_archive_sha256: "f".repeat(64),
            previous_repository_lineage: candidate.repository_lineage.clone(),
            candidate_release: candidate.release,
            candidate_archive_sha256: candidate.archive_sha256.clone(),
            candidate_rejection_sha256,
            candidate_repository_lineage: candidate.repository_lineage,
            candidate_rejection_required: false,
            previous_reconciler: candidate.reconciler.clone(),
            candidate_reconciler: candidate.reconciler,
            rollback_health_failures: 0,
            phase: updated::transaction::Phase::Prepared,
        }
    }

    #[test]
    fn first_install_intent_can_only_advance_or_clear_after_its_release_commits() {
        let mut store = Store::default();
        let started = install_transaction('1', InstallPhase::Started);
        store.write_install_journal(&started).unwrap();

        let mut prepared = started.clone();
        prepared.advance(InstallPhase::Prepared).unwrap();
        store
            .write_install_journal(&prepared)
            .expect("the same install attempt may advance");
        assert!(
            store.write_install_journal(&started).is_err(),
            "the same id cannot move durable install history backward"
        );
        let mut mutated = prepared.clone();
        mutated.archive_sha256 = "e".repeat(64);
        assert!(
            store.write_install_journal(&mutated).is_err(),
            "the same id cannot replace the release identity"
        );
        assert!(
            store
                .write_install_journal(&install_transaction('2', InstallPhase::Started))
                .is_err(),
            "a second attempt cannot bury interrupted first-install recovery"
        );
        assert!(
            store.clear_install_journal().is_err(),
            "intent survives until installed state proves the commit"
        );

        store.activate(&prepared.release).unwrap();
        let mut placed = prepared.clone();
        placed.advance(InstallPhase::Placed).unwrap();
        store
            .write_install_journal(&placed)
            .expect("placement can be recorded only after its pointer is durable");
        let mut premature_commit = placed.clone();
        premature_commit.advance(InstallPhase::Committed).unwrap();
        assert!(
            store.write_install_journal(&premature_commit).is_err(),
            "a terminal phase cannot substitute for the exact installed record"
        );

        store.memory_backend_mut().installed = Some(InstalledState::proven(
            prepared.repository_lineage.clone(),
            prepared.release.clone(),
            "e".repeat(64),
            prepared.reconciler.clone(),
        ));
        assert!(
            store.clear_install_journal().is_err(),
            "the same ReleaseId cannot conceal substituted deployed bytes"
        );

        store.memory_backend_mut().installed = Some(InstalledState::proven(
            prepared.repository_lineage.clone(),
            prepared.release.clone(),
            prepared.archive_sha256.clone(),
            prepared.reconciler.clone(),
        ));
        store
            .write_install_journal(&premature_commit)
            .expect("the exact deployed unit authorizes the terminal barrier");
        store
            .clear_install_journal()
            .expect("the exact committed release discharges first-install intent");
        assert!(store.memory_backend().install_journal.is_none());
    }

    #[test]
    fn rejection_never_authorizes_reinstalling_an_existing_release() {
        let tx = install_transaction('1', InstallPhase::Started);
        let head = InstalledState::provisional(
            tx.repository_lineage,
            tx.release,
            tx.archive_sha256,
            tx.reconciler,
        );
        let mut replacement = install_transaction('2', InstallPhase::Started);
        replacement.release.version = "0.9.0".into();
        replacement.archive_sha256 = "f".repeat(64);
        let mut store = Store::memory(MemoryBackend {
            installed: Some(head.clone()),
            active: Some(head.release.clone()),
            ..Default::default()
        });
        assert!(store.write_install_journal(&replacement).is_err());
        store
            .reject_deployment(&head.repository_lineage, &head.archive_sha256)
            .unwrap();
        assert!(store.write_install_journal(&replacement).is_err());
        // Even a planted later-phase first-install journal cannot replace committed evidence.
        replacement.phase = InstallPhase::Placed;
        store.memory_backend_mut().install_journal = Some(replacement.clone());
        let next = InstalledState::provisional(
            replacement.repository_lineage,
            replacement.release,
            replacement.archive_sha256,
            replacement.reconciler,
        );
        assert!(store.commit_installed(&next).is_err());
        assert_eq!(store.memory_backend().installed.as_ref(), Some(&head));
    }

    #[test]
    fn runtime_rejection_blocks_deployment_but_allows_exact_byte_repair() {
        let tx = install_transaction('1', InstallPhase::Started);
        let mut store = Store::default();
        store
            .reject_deployment(&tx.repository_lineage, &tx.archive_sha256)
            .unwrap();
        assert!(store.rejects_deployment(&tx.repository_lineage, &tx.archive_sha256));
        assert!(!store.is_rejected(&tx.repository_lineage, &tx.archive_sha256));
        store
            .reject_artifact(&tx.repository_lineage, &tx.archive_sha256)
            .unwrap();
        assert!(store.is_rejected(&tx.repository_lineage, &tx.archive_sha256));
    }

    #[test]
    fn update_intent_cannot_be_rewritten_while_it_is_still_discardable() {
        let started = update_transaction();
        let installed = InstalledState::proven(
            started.previous_repository_lineage.clone(),
            started.previous_release.clone(),
            started.previous_archive_sha256.clone(),
            started.previous_reconciler.clone(),
        );
        let mut store = Store::memory(MemoryBackend {
            active: Some(installed.release.clone()),
            installed: Some(installed),
            ..MemoryBackend::default()
        });
        store.write_journal(&started).unwrap();

        let mut mutated = started.clone();
        mutated.candidate_archive_sha256 = "e".repeat(64);
        assert!(
            store.write_journal(&mutated).is_err(),
            "a pre-activation journal is discardable, but its identity is not mutable under the same id"
        );
        assert_eq!(store.journal().unwrap(), Some(started));
    }

    #[test]
    fn durable_intent_cannot_be_created_after_its_initial_barrier() {
        let mut skipped_update = update_transaction();
        skipped_update
            .advance(updated::transaction::Phase::Activated)
            .unwrap();
        let mut store = Store::default();
        assert!(
            store.write_journal(&skipped_update).is_err(),
            "a fresh update journal must begin at Prepared"
        );

        let mut skipped_install = install_transaction('1', InstallPhase::Started);
        skipped_install.advance(InstallPhase::Prepared).unwrap();
        assert!(
            store.write_install_journal(&skipped_install).is_err(),
            "a fresh install journal must begin at Started"
        );
    }

    #[test]
    fn update_and_install_intent_are_mutually_exclusive_at_both_write_boundaries() {
        let update = update_transaction();
        let installed = InstalledState::proven(
            update.previous_repository_lineage.clone(),
            update.previous_release.clone(),
            update.previous_archive_sha256.clone(),
            update.previous_reconciler.clone(),
        );
        let install = install_transaction('1', InstallPhase::Started);
        let mut update_store = Store::memory(MemoryBackend {
            installed: Some(installed.clone()),
            active: Some(installed.release),
            install_journal: Some(install.clone()),
            ..MemoryBackend::default()
        });
        assert!(
            update_store.write_journal(&update).is_err(),
            "an update cannot become durable beside first-install recovery intent"
        );
        assert!(update_store.memory_backend().journal.is_none());

        let mut install_store = Store::memory(MemoryBackend {
            journal: Some(update.clone()),
            ..MemoryBackend::default()
        });
        assert!(
            install_store.write_install_journal(&install).is_err(),
            "a first install cannot become durable beside update recovery intent"
        );
        assert!(install_store.memory_backend().install_journal.is_none());

        // The exclusion applies to recovery replays too, not just new transaction ids.
        install_store.memory_backend_mut().install_journal = Some(install.clone());
        assert!(install_store.write_install_journal(&install).is_err());
        update_store.memory_backend_mut().journal = Some(update.clone());
        assert!(update_store.write_journal(&update).is_err());
    }

    #[test]
    fn executable_identity_cannot_change_without_matching_durable_intent() {
        let tx = update_transaction();
        let current = InstalledState::proven(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.previous_reconciler.clone(),
        );
        let candidate = InstalledState::provisional(
            tx.candidate_repository_lineage,
            tx.candidate_release.clone(),
            tx.candidate_archive_sha256,
            Box::new(ReconcilerRelease {
                definition_sha256: "1".repeat(64),
                ..(*tx.candidate_reconciler).clone()
            }),
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(current.clone()),
            active: Some(current.release.clone()),
            ..MemoryBackend::default()
        });

        store.activate(&candidate.release).unwrap();
        assert!(
            store.commit_installed(&candidate).is_err(),
            "activation alone is not authority to replace the committed executable identity"
        );
        assert!(matches!(
            store.installed().unwrap(),
            Installed::Present(installed) if *installed == current
        ));
    }

    #[test]
    fn update_intent_binds_the_candidate_application_and_reconciler_as_one_unit() {
        let mut tx = update_transaction();
        let current = InstalledState::proven(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.previous_reconciler.clone(),
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(current.clone()),
            active: Some(current.release),
            ..MemoryBackend::default()
        });
        store.write_journal(&tx).unwrap();
        tx.advance(updated::transaction::Phase::Activated).unwrap();
        store.write_journal(&tx).unwrap();
        tx.advance(updated::transaction::Phase::Converged).unwrap();
        store.write_journal(&tx).unwrap();
        tx.advance(updated::transaction::Phase::Verified).unwrap();
        store.write_journal(&tx).unwrap();
        store.activate(&tx.candidate_release).unwrap();

        let mut terminal = tx.clone();
        terminal
            .advance(updated::transaction::Phase::Committed)
            .unwrap();
        assert!(
            store.write_journal(&terminal).is_err(),
            "a terminal phase is not proof that the candidate commit landed"
        );

        let intended = InstalledState {
            repository_lineage: tx.candidate_repository_lineage.clone(),
            release: tx.candidate_release.clone(),
            archive_sha256: tx.candidate_archive_sha256.clone(),
            reconciler: tx.candidate_reconciler.clone(),
            rollback_guard: Some(updated::state::RollbackGuard {
                attempt_id: tx.id.clone(),
                candidate_rejection_sha256: tx.candidate_rejection_sha256.clone(),
                previous_release: tx.previous_release.clone(),
                previous_archive_sha256: tx.previous_archive_sha256.clone(),
                previous_repository_lineage: tx.previous_repository_lineage.clone(),
                reconciler: tx.previous_reconciler.clone(),
                committed_at: 1,
            }),
            maturity: updated::state::Maturity::Proven,
        };
        let mut substituted = intended.clone();
        substituted.reconciler.definition_sha256 = "1".repeat(64);
        assert!(
            store.commit_installed(&substituted).is_err(),
            "a journal for the candidate app may not authorize an adjacent reconciler"
        );
        store
            .commit_installed(&intended)
            .expect("the exact transaction-bound deployed unit commits");
        store
            .write_journal(&terminal)
            .expect("terminality becomes durable only after the exact commit exists");
    }

    #[test]
    fn terminal_rollback_cannot_erase_unsettled_state_or_rejection_evidence() {
        let mut tx = update_transaction();
        tx.phase = updated::transaction::Phase::RolledBack;
        tx.candidate_rejection_required = true;
        let predecessor = InstalledState::proven(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.previous_reconciler.clone(),
        );
        let candidate = InstalledState::proven(
            tx.candidate_repository_lineage.clone(),
            tx.candidate_release.clone(),
            tx.candidate_archive_sha256.clone(),
            tx.candidate_reconciler.clone(),
        );
        let mut store = Store::memory(MemoryBackend {
            journal: Some(tx.clone()),
            installed: Some(candidate),
            active: Some(tx.previous_release.clone()),
            ..MemoryBackend::default()
        });
        assert!(
            store.clear_journal().is_err(),
            "RolledBack cannot erase the journal while installed state still names the candidate"
        );

        store.memory_backend_mut().installed = Some(predecessor);
        assert!(
            store.clear_journal().is_err(),
            "the restored predecessor does not discharge a required candidate rejection"
        );
        store.memory_backend_mut().fail_reject = true;
        assert!(store
            .reject_deployment(
                &tx.candidate_repository_lineage,
                &tx.candidate_archive_sha256
            )
            .is_err());
        assert!(store.rejects_deployment(
            &tx.candidate_repository_lineage,
            &tx.candidate_archive_sha256
        ));
        assert!(
            store.clear_journal().is_err(),
            "live suppression is not durable evidence"
        );
        store.memory_backend_mut().fail_reject = false;
        assert!(
            store.clear_journal().is_err(),
            "restoring storage alone does not persist the verdict"
        );
        store
            .reject_deployment(
                &tx.candidate_repository_lineage,
                &tx.candidate_archive_sha256,
            )
            .unwrap();
        store
            .clear_journal()
            .expect("full rollback state and rejection evidence discharge the journal");
    }

    #[test]
    fn pending_rollback_cannot_erase_its_candidate_rejection_identity() {
        let tx = update_transaction();
        let candidate = InstalledState {
            repository_lineage: tx.candidate_repository_lineage.clone(),
            release: tx.candidate_release,
            archive_sha256: tx.candidate_archive_sha256,
            reconciler: tx.candidate_reconciler,
            rollback_guard: Some(updated::state::RollbackGuard {
                attempt_id: tx.id,
                candidate_rejection_sha256: tx.candidate_rejection_sha256.clone(),
                previous_release: tx.previous_release.clone(),
                previous_archive_sha256: tx.previous_archive_sha256.clone(),
                previous_repository_lineage: tx.previous_repository_lineage.clone(),
                reconciler: tx.previous_reconciler.clone(),
                committed_at: 1,
            }),
            maturity: updated::state::Maturity::Proven,
        };
        let predecessor = InstalledState::proven(
            tx.previous_repository_lineage,
            tx.previous_release.clone(),
            tx.previous_archive_sha256,
            tx.previous_reconciler,
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(candidate.clone()),
            active: Some(tx.previous_release),
            ..MemoryBackend::default()
        });

        assert!(
            store.commit_installed(&predecessor).is_err(),
            "pending cannot disappear before its candidate rejection is durable"
        );
        store.memory_backend_mut().fail_reject = true;
        assert!(store
            .reject_deployment(&candidate.repository_lineage, &candidate.archive_sha256)
            .is_err());
        assert!(store.commit_installed(&predecessor).is_err());
        store.memory_backend_mut().fail_reject = false;
        assert!(store.commit_installed(&predecessor).is_err());
        store
            .reject_deployment(&candidate.repository_lineage, &candidate.archive_sha256)
            .unwrap();
        store
            .commit_installed(&predecessor)
            .expect("the exact pending rollback settles after its rejection is durable");
    }

    #[test]
    fn activation_has_one_ordered_fail_closed_path() {
        let predecessor = ReleaseId {
            version: "0.9.0".into(),
            manifest_sha256: "a".repeat(64),
        };
        let candidate = ReleaseId {
            version: "1.0.0".into(),
            manifest_sha256: "b".repeat(64),
        };

        let mut corrupt = Store::memory(MemoryBackend {
            active: Some(predecessor.clone()),
            fail_verify_release: true,
            ..MemoryBackend::default()
        });
        assert_eq!(
            corrupt.activate(&candidate).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(corrupt.memory_backend().active, Some(predecessor.clone()));

        let mut unwritable = Store::memory(MemoryBackend {
            active: Some(predecessor.clone()),
            fail_point_active: true,
            ..MemoryBackend::default()
        });
        assert!(unwritable.activate(&candidate).is_err());
        assert_eq!(unwritable.memory_backend().active, Some(predecessor));

        let mut healthy = Store::default();
        healthy.activate(&candidate).unwrap();
        assert_eq!(healthy.memory_backend().active, Some(candidate));
    }

    #[test]
    fn every_backend_refuses_the_same_invalid_installed_state() {
        let transaction = install_transaction('1', InstallPhase::Started);
        let mut state = InstalledState::proven(
            transaction.repository_lineage,
            transaction.release,
            transaction.archive_sha256,
            transaction.reconciler,
        );
        state.archive_sha256 = "not-a-digest".into();

        let mut store = Store::default();
        assert_eq!(
            store.commit_installed(&state).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(store.memory_backend().installed.is_none());
        assert!(
            store.is_rejected(
                &RepositoryLineage::from_metadata_url("https://repo.example/metadata/")
                    .expect("fixture metadata URL is valid"),
                "not-a-digest"
            ),
            "an identity the rejection store cannot represent must fail closed"
        );
    }

    #[test]
    fn installed_state_can_only_commit_the_active_release() {
        let transaction = install_transaction('1', InstallPhase::Started);
        let state = InstalledState::proven(
            transaction.repository_lineage,
            transaction.release.clone(),
            transaction.archive_sha256,
            transaction.reconciler,
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(state.clone()),
            ..MemoryBackend::default()
        });

        assert_eq!(
            store.commit_installed(&state).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let other = ReleaseId {
            version: "2.0.0".into(),
            manifest_sha256: "9".repeat(64),
        };
        store.activate(&other).unwrap();
        assert_eq!(
            store.commit_installed(&state).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        store.activate(&state.release).unwrap();
        store.commit_installed(&state).unwrap();
        assert!(matches!(
            store.installed().unwrap(),
            Installed::Present(installed) if *installed == state
        ));
    }

    #[test]
    fn provisional_confirmation_is_one_idempotent_store_transition() {
        let transaction = install_transaction('1', InstallPhase::Started);
        let state = InstalledState::provisional(
            transaction.repository_lineage,
            transaction.release.clone(),
            transaction.archive_sha256,
            transaction.reconciler,
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(state),
            active: Some(transaction.release),
            ..MemoryBackend::default()
        });

        assert!(store.prove_provisional().unwrap());
        assert!(matches!(
            store.installed().unwrap(),
            Installed::Present(installed) if installed.is_proven() && installed.rollback_guard.is_none()
        ));
        assert!(!store.prove_provisional().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn confirmation_preserves_a_windows_replace_fault_for_the_retry_boundary() {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

        let directory = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(directory.path(), &directory.path().join("enrollment"));
        let mut store = Store::open(paths.clone()).unwrap();
        let source = directory.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("app.exe"), b"fixture").unwrap();
        let archive = directory.path().join("app.tar.zst");
        let platform = foundation::platform::platform_key();
        updated::bundle::create_bundle(&source, &archive, "app", "1.0.0", &platform).unwrap();
        let release = updated::bundle_store::BundleStore::for_app(&paths)
            .install(
                &archive,
                &updated::bundle::ExpectedBundle {
                    product: "app",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();

        let mut transaction = install_transaction('1', InstallPhase::Started);
        transaction.release = release;
        store.write_install_journal(&transaction).unwrap();
        transaction.advance(InstallPhase::Prepared).unwrap();
        store.write_install_journal(&transaction).unwrap();
        store.activate(&transaction.release).unwrap();
        transaction.advance(InstallPhase::Placed).unwrap();
        store.write_install_journal(&transaction).unwrap();
        let state = InstalledState::provisional(
            transaction.repository_lineage.clone(),
            transaction.release.clone(),
            transaction.archive_sha256.clone(),
            transaction.reconciler.clone(),
        );
        store.commit_installed(&state).unwrap();
        transaction.advance(InstallPhase::Committed).unwrap();
        store.write_install_journal(&transaction).unwrap();
        store.clear_install_journal().unwrap();

        // Confirmation first reads installed.json, then atomically replaces it. Keep reads legal
        // while withholding delete sharing so this exercises the replacement boundary itself.
        let replacement_blocker = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&paths.installed)
            .unwrap();
        assert!(matches!(store.installed().unwrap(), Installed::Present(_)));
        let error = store.prove_provisional().unwrap_err();
        assert!(
            crate::transient::is_node_local_transient(&error),
            "the atomic replacement must retain the sharing violation: {error:?}"
        );

        drop(replacement_blocker);
        assert!(store.prove_provisional().unwrap());
    }

    #[test]
    fn the_memory_backend_reads_durable_values_through_the_production_validators() {
        let mut invalid_installed = InstalledState::proven(
            RepositoryLineage::from_metadata_url("https://repo.example/metadata/")
                .expect("fixture metadata URL is valid"),
            ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: "a".repeat(64),
            },
            "b".repeat(64),
            install_transaction('1', InstallPhase::Started).reconciler,
        );
        invalid_installed.archive_sha256 = "bad".into();

        let mut invalid_update = update_transaction();
        invalid_update.id = "bad".into();
        let mut invalid_install = install_transaction('2', InstallPhase::Started);
        invalid_install.id = "bad".into();
        let invalid_active = ReleaseId {
            version: "1.0.0".into(),
            manifest_sha256: "bad".into(),
        };
        let store = Store::memory(MemoryBackend {
            installed: Some(invalid_installed),
            journal: Some(invalid_update),
            install_journal: Some(invalid_install),
            active: Some(invalid_active),
            ..MemoryBackend::default()
        });

        assert!(matches!(store.installed().unwrap(), Installed::Invalid));
        assert_eq!(
            store.journal().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            store.install_journal().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            store.active_release().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
