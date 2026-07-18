use std::io;
use std::time::Duration;

use updated::bundle::{read_active, write_active, ReleaseId};
use updated::config::Paths;
use updated::reject::Rejections;
use updated::state::{read_installed, write_installed, Installed, InstalledState};
use updated::transaction::{self, Transaction};

pub(crate) trait Store {
    fn installed(&self) -> Installed;
    fn journal(&self) -> io::Result<Option<Transaction>>;
    fn active_release(&self) -> io::Result<Option<ReleaseId>>;
    fn is_rejected(&self, digest: &str) -> bool;
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()>;
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    fn clear_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, digest: &str) -> io::Result<()>;
    fn clear_rejection(&mut self, digest: &str) -> io::Result<()>;
    fn activate(&mut self, release: &ReleaseId) -> io::Result<()>;
}

pub(crate) struct FileStore {
    pub(crate) paths: Paths,
    rejected: Rejections,
}

impl FileStore {
    pub(crate) fn open(paths: Paths, retry_after: Duration) -> io::Result<Self> {
        std::fs::create_dir_all(&paths.versions)?;
        std::fs::create_dir_all(&paths.staging)?;
        if let Some(parent) = paths.state.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let rejected = Rejections::load(&paths.rejected, retry_after)?;
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
    fn active_release(&self) -> io::Result<Option<ReleaseId>> {
        read_active(&self.paths.active_release)
    }
    fn is_rejected(&self, digest: &str) -> bool {
        self.rejected.is_rejected(digest)
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
    fn reject(&mut self, digest: &str) -> io::Result<()> {
        self.rejected.reject(digest)
    }
    fn clear_rejection(&mut self, digest: &str) -> io::Result<()> {
        self.rejected.clear(digest)
    }
    fn activate(&mut self, release: &ReleaseId) -> io::Result<()> {
        // Verification is an ingest-time gate (see `stage_bundle`); the committed store is
        // trusted here. Activation just moves the atomic active-release pointer.
        write_active(&self.paths.active_release, release)
    }
}
