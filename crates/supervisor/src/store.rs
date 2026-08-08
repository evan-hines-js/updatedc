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
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    fn clear_journal(&mut self) -> io::Result<()>;
    fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()>;
    fn clear_install_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()>;
    fn clear_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()>;
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
}

pub(crate) struct FileStore {
    pub(crate) paths: Paths,
    rejected: Rejections,
}

impl FileStore {
    pub(crate) fn open(paths: Paths) -> io::Result<Self> {
        std::fs::create_dir_all(&paths.versions)?;
        std::fs::create_dir_all(&paths.staging)?;
        if let Some(parent) = paths.state.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let rejected = Rejections::load(&paths.rejected)?;
        Ok(Self { paths, rejected })
    }
}

impl Store for FileStore {
    fn installed(&self) -> Installed {
        read_installed(&self.paths.state)
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
        write_installed(&self.paths.state, state)
    }
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        transaction::write(&self.paths.journal, tx)
    }
    fn clear_journal(&mut self) -> io::Result<()> {
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
    fn clear_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
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
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        self.journal = Some(tx.clone());
        Ok(())
    }
    fn clear_journal(&mut self) -> io::Result<()> {
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
    fn clear_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
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
