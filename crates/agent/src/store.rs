use std::io;

use updated::bundle::{read_active, write_active, ReleaseId};
use updated::config::Paths;
use updated::install::InstallTransaction;
use updated::reject::Rejections;
use updated::state::{
    read_installed, write_installed, Installed, InstalledState, RepositoryLineage,
};
use updated::transaction::Transaction;

pub(crate) trait Store {
    fn installed(&self) -> Installed;
    fn journal(&self) -> io::Result<Option<Transaction>>;
    fn install_journal(&self) -> io::Result<Option<InstallTransaction>>;
    fn active_release(&self) -> io::Result<Option<ReleaseId>>;
    fn is_rejected(&self, lineage: &RepositoryLineage, digest: &str) -> bool;
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()>;
    /// Write the journal bytes, unconditionally. The implementation detail behind
    /// [`Store::write_journal`] — call that instead: it is the one place the replace rule is
    /// enforced, and a direct `record_journal` can silently bury another transaction's
    /// compensation obligation.
    fn record_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    /// Remove the journal file, unconditionally. The implementation detail behind
    /// [`Store::clear_journal`] — call that instead: it is the one place the discard rule is
    /// enforced, and a direct `remove_journal` bypasses the machine's compensation guarantee.
    fn remove_journal(&mut self) -> io::Result<()>;
    /// Write first-install journal bytes unconditionally. The implementation detail behind
    /// [`Store::write_install_journal`].
    fn record_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()>;
    /// Remove first-install journal bytes unconditionally. The implementation detail behind
    /// [`Store::clear_install_journal`].
    fn remove_install_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()>;
    /// Delete a rejection record, unconditionally. The implementation detail behind
    /// [`Store::clear_rejection`] — call that instead: a rejection is never-retry evidence, and
    /// only proof that the same bytes later succeeded may erase it.
    fn remove_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()>;
    /// Re-hash the exact bytes a pointer is about to name. Ingest verifies a release once, but
    /// activation runs again on paths that never re-checked *these* bytes (a crash-recovered
    /// rollback activates the PREDECESSOR; drift restore re-points at the committed release), so
    /// predecessor bytes are never launched unverified even for one boot. A failure here means the
    /// on-disk bytes are corrupt — the release's fault — so callers reject it.
    fn verify_release(&self, release: &ReleaseId) -> io::Result<()>;
    /// Move the durable active-release pointer to `release` WITHOUT re-verifying. A failure is pure
    /// infrastructure (ENOSPC, transient I/O on the atomic write), never the release's fault, so
    /// callers recover rather than permanently reject a healthy release.
    fn point_active(&mut self, release: &ReleaseId) -> io::Result<()>;
    /// Verify then point — the combined gate for the recovery/rollback/repair paths that want both
    /// in one step. The forward-update path splits them so it can attribute failure correctly.
    fn activate(&mut self, release: &ReleaseId) -> io::Result<()> {
        self.verify_release(release)?;
        self.point_active(release)
    }
    /// Destroy the journal — but only when its transaction no longer owes the machine anything.
    /// Two ways a journal can be owed nothing, each with its single existing definition:
    /// [`Transaction::may_discard`] answers from the phase alone (nothing displaced yet, or a
    /// terminal phase — and reaching `RolledBack` is what runs, or durably abandons, the
    /// compensating `rollback` hook); and [`classify_recovery`]'s `Committed` answers from the
    /// machine — a crash between the durable commit and the journal's own terminal write leaves
    /// the phase at `Committing` while active and installed state prove the commit landed.
    /// Every other case is displaced state with an obligation on record, and discarding the
    /// record would silently skip the compensation — so the refusal lives here, on the destroy
    /// operation itself, where no future call site can forget it.
    fn clear_journal(&mut self) -> io::Result<()> {
        if let Some(tx) = self.journal()? {
            let committed = match self.installed() {
                Installed::Present(state) => Some(state.release.clone()),
                Installed::Missing | Installed::Invalid => None,
            };
            let landed = matches!(
                updated::transaction::classify_recovery(
                    &tx,
                    self.active_release()?.as_ref(),
                    committed.as_ref(),
                ),
                updated::transaction::Recovery::Committed
            );
            if !tx.may_discard() && !landed {
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
    /// Persist a transaction without rewriting its identity or its durable history. Until a
    /// transaction settles, a same-id record must be one exact successor; a different id may
    /// replace it only while nothing has been displaced. Burying unsettled evidence is the same
    /// destruction [`Store::clear_journal`] refuses, through a different door.
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        if let Some(existing) = self.journal()? {
            if existing.id != tx.id && !existing.may_discard() {
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
            if existing.id == tx.id && !existing.permits_replacement(tx) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing an invalid rewrite of transaction {} from {:?} to {:?}",
                        existing.id, existing.phase, tx.phase
                    ),
                ));
            }
        }
        self.record_journal(tx)
    }
    /// Persist first-install intent without ever burying a different interrupted install. An
    /// install has no abort path: every non-committed record is resumed, and a committed record is
    /// cleared before a later install can begin. Replays and phase advances of the same attempt are
    /// the only legitimate replacement.
    fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
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
        }
        self.record_install_journal(tx)
    }
    /// Destroy first-install intent only after the authoritative installed record proves the exact
    /// release committed. Phase alone is insufficient: preserving the journal when installed
    /// state is missing or corrupt is what keeps an interrupted enrollment recoverable.
    fn clear_install_journal(&mut self) -> io::Result<()> {
        if let Some(tx) = self.install_journal()? {
            let installed = match self.installed() {
                Installed::Present(state) => Some(state.release.clone()),
                Installed::Missing | Installed::Invalid => None,
            };
            if !matches!(
                updated::install::classify_install_recovery(&tx, installed.as_ref()),
                updated::install::InstallRecovery::Committed
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to discard first-install transaction {} at {:?}: its release is not committed",
                        tx.id, tx.phase
                    ),
                ));
            }
        }
        self.remove_install_journal()
    }
    /// Erase a rejection — but only with proof of settlement: the exact rejected bytes are the
    /// currently committed head, so the machine itself has demonstrated they work. A rejection is
    /// the durable reason a release is never retried; erasing one on any weaker evidence
    /// re-admits bytes the machine judged bad.
    fn clear_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        let settled = matches!(
            self.installed(),
            Installed::Present(ref state)
                if state.repository_lineage.rejection_key(&state.archive_sha256)
                    == lineage.rejection_key(digest)
        );
        if !settled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to erase a rejection for bytes that are not the committed head",
            ));
        }
        self.remove_rejection(lineage, digest)
    }
}

pub(crate) struct FileStore {
    pub(crate) paths: Paths,
    rejected: Rejections,
}

impl FileStore {
    pub(crate) fn open(paths: Paths) -> io::Result<Self> {
        std::fs::create_dir_all(&paths.versions)?;
        std::fs::create_dir_all(&paths.staging)?;
        std::fs::create_dir_all(&paths.state_dir)?;
        let rejected = Rejections::load(&paths.rejected)?;
        Ok(Self { paths, rejected })
    }
}

impl Store for FileStore {
    fn installed(&self) -> Installed {
        read_installed(&self.paths.installed)
    }
    fn journal(&self) -> io::Result<Option<Transaction>> {
        updated::journal::read(&self.paths.journal)
    }
    fn install_journal(&self) -> io::Result<Option<InstallTransaction>> {
        updated::journal::read(&self.paths.install_journal)
    }
    fn active_release(&self) -> io::Result<Option<ReleaseId>> {
        read_active(&self.paths.active_release)
    }
    fn is_rejected(&self, lineage: &RepositoryLineage, digest: &str) -> bool {
        self.rejected.is_rejected(&lineage.rejection_key(digest))
    }
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
        write_installed(&self.paths.installed, state)
    }
    fn record_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        updated::journal::write(&self.paths.journal, tx)
    }
    fn remove_journal(&mut self) -> io::Result<()> {
        updated::journal::clear(&self.paths.journal)
    }
    fn record_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        updated::journal::write(&self.paths.install_journal, tx)
    }
    fn remove_install_journal(&mut self) -> io::Result<()> {
        updated::journal::clear(&self.paths.install_journal)
    }
    fn reject(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        self.rejected.reject(&lineage.rejection_key(digest))
    }
    fn remove_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        self.rejected.clear(&lineage.rejection_key(digest))
    }
    fn verify_release(&self, release: &ReleaseId) -> io::Result<()> {
        updated::bundle::verify_release(&self.paths.versions, release)
    }
    fn point_active(&mut self, release: &ReleaseId) -> io::Result<()> {
        write_active(&self.paths.active_release, release)
    }
}

/// The crate's one in-memory [`Store`], for tests that drive boot recovery and the update
/// transaction across simulated boots without touching a filesystem. There is exactly one so the
/// two paths cannot be tested against two different notions of what the durable layer does —
/// rejections really are keyed by lineage here, and the install journal really is modelled.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemStore {
    pub(crate) installed: Option<InstalledState>,
    pub(crate) journal: Option<Transaction>,
    pub(crate) install_journal: Option<InstallTransaction>,
    pub(crate) active: Option<ReleaseId>,
    pub(crate) rejected: std::collections::HashSet<String>,
    /// Simulate a state directory that has gone unwritable (ENOSPC, a read-only remount).
    pub(crate) fail_reject: bool,
}

#[cfg(test)]
impl Store for MemStore {
    fn installed(&self) -> Installed {
        match &self.installed {
            Some(state) => Installed::Present(Box::new(state.clone())),
            None => Installed::Missing,
        }
    }
    fn journal(&self) -> io::Result<Option<Transaction>> {
        Ok(self.journal.clone())
    }
    fn install_journal(&self) -> io::Result<Option<InstallTransaction>> {
        Ok(self.install_journal.clone())
    }
    fn active_release(&self) -> io::Result<Option<ReleaseId>> {
        Ok(self.active.clone())
    }
    fn is_rejected(&self, lineage: &RepositoryLineage, digest: &str) -> bool {
        self.rejected.contains(&lineage.rejection_key(digest))
    }
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
        self.installed = Some(state.clone());
        Ok(())
    }
    fn record_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        self.journal = Some(tx.clone());
        Ok(())
    }
    fn remove_journal(&mut self) -> io::Result<()> {
        self.journal = None;
        Ok(())
    }
    fn record_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        self.install_journal = Some(tx.clone());
        Ok(())
    }
    fn remove_install_journal(&mut self) -> io::Result<()> {
        self.install_journal = None;
        Ok(())
    }
    fn reject(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        if self.fail_reject {
            return Err(io::Error::other("injected rejection write failure"));
        }
        self.rejected.insert(lineage.rejection_key(digest));
        Ok(())
    }
    fn remove_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
        self.rejected.remove(&lineage.rejection_key(digest));
        Ok(())
    }
    fn verify_release(&self, _: &ReleaseId) -> io::Result<()> {
        Ok(())
    }
    fn point_active(&mut self, release: &ReleaseId) -> io::Result<()> {
        self.active = Some(release.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use updated::install::InstallPhase;
    use updated::state::ProviderRelease;

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
            ),
            lifecycle: Box::new(ProviderRelease {
                provider_set_sha256: "c".repeat(64),
                product: "reconciler".into(),
                release,
                archive_sha256: "d".repeat(64),
                args: Vec::new(),
                timeout_millis: 1_000,
            }),
            phase,
        }
    }

    fn update_transaction() -> Transaction {
        let candidate = install_transaction('3', InstallPhase::Started);
        Transaction {
            id: "4".repeat(64),
            previous_release: ReleaseId {
                version: "0.9.0".into(),
                manifest_sha256: "e".repeat(64),
            },
            previous_archive_sha256: "f".repeat(64),
            previous_repository_lineage: candidate.repository_lineage.clone(),
            candidate_release: candidate.release,
            candidate_archive_sha256: candidate.archive_sha256,
            candidate_rejection_sha256: "a".repeat(64),
            candidate_repository_lineage: candidate.repository_lineage,
            candidate_rejection_required: false,
            lifecycle: candidate.lifecycle,
            rollback_health_failures: 0,
            phase: updated::transaction::Phase::Prepared,
        }
    }

    #[test]
    fn first_install_intent_can_only_advance_or_clear_after_its_release_commits() {
        let mut store = MemStore::default();
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

        store.installed = Some(InstalledState::confirmed(
            prepared.repository_lineage.clone(),
            prepared.release.clone(),
            prepared.archive_sha256.clone(),
            prepared.lifecycle.clone(),
        ));
        store
            .clear_install_journal()
            .expect("the exact committed release discharges first-install intent");
        assert!(store.install_journal.is_none());
    }

    #[test]
    fn update_intent_cannot_be_rewritten_while_it_is_still_discardable() {
        let mut store = MemStore::default();
        let started = update_transaction();
        store.write_journal(&started).unwrap();

        let mut mutated = started.clone();
        mutated.candidate_archive_sha256 = "e".repeat(64);
        assert!(
            store.write_journal(&mutated).is_err(),
            "a pre-activation journal is discardable, but its identity is not mutable under the same id"
        );
        assert_eq!(store.journal().unwrap(), Some(started));
    }
}
