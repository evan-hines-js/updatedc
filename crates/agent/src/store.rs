use std::io;

use updated::bundle::{read_active, write_active, ReleaseId};
use updated::config::Paths;
use updated::install::{self, InstallTransaction};
use updated::reject::Rejections;
use updated::state::{
    read_installed, write_installed, Installed, InstalledState, RepositoryLineage,
};
use updated::transaction::{self, Transaction};

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
    fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()>;
    fn clear_install_journal(&mut self) -> io::Result<()>;
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
    /// [`Transaction::may_discard`] is the rule: before `ActivateStarted` nothing was displaced,
    /// and `Committed`/`RolledBack` have settled their debt (reaching `RolledBack` is what runs,
    /// or durably abandons, the compensating `rollback` hook). Every other phase is a machine
    /// whose displaced state still has an obligation on record, and discarding the record would
    /// silently skip the compensation — so the refusal lives here, on the destroy operation
    /// itself, where no future call site can forget it.
    fn clear_journal(&mut self) -> io::Result<()> {
        if let Some(tx) = self.journal()? {
            if !tx.may_discard() {
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
    /// Persist a transaction — but never over a DIFFERENT transaction that still owes the
    /// machine anything. Replays and phase advances of the same transaction (same id) pass
    /// freely; burying another unsettled journal is the same evidence destruction as
    /// [`Store::clear_journal`] refuses, through a different door.
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
        }
        self.record_journal(tx)
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
        transaction::read(&self.paths.journal)
    }
    fn install_journal(&self) -> io::Result<Option<InstallTransaction>> {
        install::read(&self.paths.install_journal)
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
        transaction::write(&self.paths.journal, tx)
    }
    fn remove_journal(&mut self) -> io::Result<()> {
        transaction::clear(&self.paths.journal)
    }
    fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        install::write(&self.paths.install_journal, tx)
    }
    fn clear_install_journal(&mut self) -> io::Result<()> {
        install::clear(&self.paths.install_journal)
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
    fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
        self.install_journal = Some(tx.clone());
        Ok(())
    }
    fn clear_install_journal(&mut self) -> io::Result<()> {
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
