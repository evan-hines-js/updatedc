//! The supervisor's durable-state port.
//!
//! Every piece of on-disk state the update transaction touches — the installed-state
//! record, the transaction journal, the rejected-release set, and the application binary
//! itself (its hash, the retained rollback image, the atomic swap) — is reached through
//! this one trait. The shell owns a [`FileStore`]; tests own a [`MemStore`] and can
//! fault-inject a write failing mid-commit, so the crash-safety of the transaction and its
//! recovery is provable in a unit test, not only in an e2e chaos run.

use std::io;

use updated::config::Paths;
use updated::reject::Rejections;
use updated::state::{read_installed, write_installed, Installed, InstalledState};

use crate::domain::Transaction;
use updated::hash::{sha256_file, verify_file};

/// The durable state the update transaction reads and writes. Reads are `&self`, mutations
/// `&mut self`. Binary operations preserve the crash-safety contract: a swap retains the
/// previous bytes as a rollback image, and a restore reinstates and verifies them.
pub(crate) trait Store {
    // ----------------------------------- reads ------------------------------------
    fn installed(&self) -> Installed;
    fn journal(&self) -> io::Result<Option<Transaction>>;
    /// Hash of the live application binary (`None` if unreadable / absent).
    fn binary_sha(&self) -> Option<String>;
    /// Hash of the retained `<binary>.old` rollback image (`None` if absent).
    fn rollback_sha(&self) -> Option<String>;
    fn is_rejected(&self, sha: &str) -> bool;

    // ------------------------------- durable writes -------------------------------
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()>;
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    fn clear_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, sha: &str) -> io::Result<()>;
    fn clear_rejection(&mut self, sha: &str) -> io::Result<()>;

    // ----------------------------- binary transaction -----------------------------
    /// Verify the live binary hashes to `sha`; `Err` (fail closed) if it does not.
    fn verify_binary(&self, sha: &str) -> io::Result<()>;
    /// Atomically swap the staged download in as the live binary, retaining the previous
    /// bytes as the `<binary>.old` rollback image.
    fn swap_in_staged(&mut self) -> io::Result<()>;
    /// Restore `<binary>.old` over the live binary, verify it hashes to `sha`, and drop the
    /// rollback copy. The single reinstatement path, used by rollback and drift recovery.
    fn restore_committed(&mut self, sha: &str) -> io::Result<()>;
    /// Drop the `<binary>.old` rollback image (an update confirmed, or never swapped).
    fn drop_rollback(&mut self);
}

// ================================= real: FileStore =================================

/// The production [`Store`]: the canonical on-disk layout ([`Paths`]) plus the loaded
/// rejected set. Every method is a thin wrapper over the same crash-safe primitives the
/// supervisor has always used, so routing through the port changes structure, not behavior.
pub(crate) struct FileStore {
    paths: Paths,
    rejected: Rejections,
}

impl FileStore {
    pub(crate) fn open(paths: Paths, retry_after: std::time::Duration) -> Self {
        let rejected = Rejections::load(&paths.rejected, retry_after);
        FileStore { paths, rejected }
    }
}

impl Store for FileStore {
    fn installed(&self) -> Installed {
        read_installed(&self.paths.state)
    }
    fn journal(&self) -> io::Result<Option<Transaction>> {
        updated::transaction::read(&self.paths.journal)
    }
    fn binary_sha(&self) -> Option<String> {
        sha256_file(&self.paths.binary).ok()
    }
    fn rollback_sha(&self) -> Option<String> {
        let old = updated::apply::old_path(&self.paths.binary);
        old.exists().then(|| sha256_file(&old).ok()).flatten()
    }
    fn is_rejected(&self, sha: &str) -> bool {
        self.rejected.is_rejected(sha)
    }
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
        write_installed(&self.paths.state, state)
    }
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        updated::transaction::write(&self.paths.journal, tx)
    }
    fn clear_journal(&mut self) -> io::Result<()> {
        // A surviving journal drives crash recovery; make its deletion durable.
        updated::transaction::clear(&self.paths.journal)
    }
    fn reject(&mut self, sha: &str) -> io::Result<()> {
        self.rejected.reject(sha)
    }
    fn clear_rejection(&mut self, sha: &str) -> io::Result<()> {
        self.rejected.clear(sha)
    }

    fn verify_binary(&self, sha: &str) -> io::Result<()> {
        verify_file(&self.paths.binary, sha)
    }
    fn swap_in_staged(&mut self) -> io::Result<()> {
        updated::apply::atomic_swap_file(&self.paths.binary, &self.paths.download)?;
        let _ = std::fs::remove_file(&self.paths.download);
        Ok(())
    }
    fn restore_committed(&mut self, sha: &str) -> io::Result<()> {
        updated::apply::rollback(&self.paths.binary)?;
        verify_file(&self.paths.binary, sha)?;
        updated::apply::cleanup_previous(&self.paths.binary);
        Ok(())
    }
    fn drop_rollback(&mut self) {
        updated::apply::cleanup_previous(&self.paths.binary);
    }
}

// ================================== fake: MemStore =================================

/// An in-memory [`Store`] for unit tests. The binary is modeled by its hash (a string
/// identity), so a swap/restore is a hash move — enough to prove the transaction and its
/// recovery are crash-safe, with faults injectable at any durable step.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemStore {
    installed: Option<InstalledState>,
    installed_invalid: bool,
    binary: Option<String>,
    rollback: Option<String>,
    staged: Option<String>,
    journal: Option<Transaction>,
    rejected: std::collections::HashSet<String>,
    /// Durable operations to fail once, to exercise the crash/error paths.
    pub faults: Faults,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    pub commit: bool,
    pub swap: bool,
    pub restore: bool,
    pub clear_journal: bool,
    pub write_journal: bool,
}

#[cfg(test)]
impl MemStore {
    /// A committed install of `version`/`sha` with matching on-disk bytes and nothing else.
    pub(crate) fn committed(version: &str, sha: &str) -> Self {
        MemStore {
            installed: Some(InstalledState::confirmed(version.into(), sha.into())),
            binary: Some(sha.into()),
            ..Default::default()
        }
    }
    pub(crate) fn set_binary(&mut self, sha: &str) {
        self.binary = Some(sha.into());
    }
    pub(crate) fn set_rollback(&mut self, sha: &str) {
        self.rollback = Some(sha.into());
    }
    pub(crate) fn set_staged(&mut self, sha: &str) {
        self.staged = Some(sha.into());
    }
    pub(crate) fn set_journal(&mut self, tx: Transaction) {
        self.journal = Some(tx);
    }
    pub(crate) fn installed_state(&self) -> Option<&InstalledState> {
        self.installed.as_ref()
    }
    pub(crate) fn has_rollback(&self) -> bool {
        self.rollback.is_some()
    }
    pub(crate) fn journal_present(&self) -> bool {
        self.journal.is_some()
    }

    fn err(what: &str) -> io::Error {
        io::Error::other(format!("injected fault: {what}"))
    }
}

#[cfg(test)]
impl Store for MemStore {
    fn installed(&self) -> Installed {
        if self.installed_invalid {
            Installed::Invalid
        } else {
            match &self.installed {
                Some(s) => Installed::Present(s.clone()),
                None => Installed::Missing,
            }
        }
    }
    fn journal(&self) -> io::Result<Option<Transaction>> {
        Ok(self.journal.clone())
    }
    fn binary_sha(&self) -> Option<String> {
        self.binary.clone()
    }
    fn rollback_sha(&self) -> Option<String> {
        self.rollback.clone()
    }
    fn is_rejected(&self, sha: &str) -> bool {
        self.rejected.contains(sha)
    }

    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
        if std::mem::take(&mut self.faults.commit) {
            return Err(Self::err("commit_installed"));
        }
        self.installed = Some(state.clone());
        self.installed_invalid = false;
        Ok(())
    }
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
        if std::mem::take(&mut self.faults.write_journal) {
            return Err(Self::err("write_journal"));
        }
        self.journal = Some(tx.clone());
        Ok(())
    }
    fn clear_journal(&mut self) -> io::Result<()> {
        if std::mem::take(&mut self.faults.clear_journal) {
            return Err(Self::err("clear_journal"));
        }
        self.journal = None;
        Ok(())
    }
    fn reject(&mut self, sha: &str) -> io::Result<()> {
        self.rejected.insert(sha.into());
        Ok(())
    }
    fn clear_rejection(&mut self, sha: &str) -> io::Result<()> {
        self.rejected.remove(sha);
        Ok(())
    }

    fn verify_binary(&self, sha: &str) -> io::Result<()> {
        if self.binary.as_deref() == Some(sha) {
            Ok(())
        } else {
            Err(Self::err("binary hash mismatch"))
        }
    }
    fn swap_in_staged(&mut self) -> io::Result<()> {
        if std::mem::take(&mut self.faults.swap) {
            return Err(Self::err("swap_in_staged"));
        }
        let staged = self
            .staged
            .take()
            .ok_or_else(|| Self::err("no staged bytes"))?;
        self.rollback = self.binary.take();
        self.binary = Some(staged);
        Ok(())
    }
    fn restore_committed(&mut self, sha: &str) -> io::Result<()> {
        if std::mem::take(&mut self.faults.restore) {
            return Err(Self::err("restore_committed"));
        }
        let old = self
            .rollback
            .take()
            .ok_or_else(|| Self::err("no rollback image"))?;
        if old != sha {
            return Err(Self::err("rollback image hash mismatch"));
        }
        self.binary = Some(old);
        Ok(())
    }
    fn drop_rollback(&mut self) {
        self.rollback = None;
    }
}

// ============================ FileStore (real adapter) ============================

#[cfg(test)]
mod file_store_tests {
    use super::*;
    use updated::config::Paths;

    fn paths_in(dir: &std::path::Path) -> Paths {
        Paths {
            binary: dir.join("app"),
            state: dir.join("app.installed"),
            datastore: dir.join("app.tuf"),
            download: dir.join("app.download"),
            journal: dir.join("app.transaction"),
            rejected: dir.join("app.rejected"),
            app_token: dir.join("app.apptoken"),
        }
    }

    // One end-to-end pass over the production adapter: each method must be wired to the
    // right on-disk primitive, so a delegation that no-ops (returns Ok(())/None/()) is
    // caught. The underlying crash-safe primitives are proven in the `updated` crate.
    #[test]
    fn file_store_round_trips_state_journal_rejections_and_binary_swap() {
        let dir = std::env::temp_dir().join(format!("filestore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = paths_in(&dir);
        std::fs::write(&paths.binary, b"v1-bytes").unwrap();
        let v1 = sha256_file(&paths.binary).unwrap();

        let mut store = FileStore::open(paths.clone(), std::time::Duration::from_secs(3600));

        // Reads reflect disk: binary hash present, no rollback, no state, no journal.
        assert_eq!(store.binary_sha(), Some(v1.clone()));
        assert!(store.rollback_sha().is_none());
        assert!(matches!(store.installed(), Installed::Missing));
        assert!(store.journal().unwrap().is_none());

        // Installed-state round-trips through the record.
        let state = InstalledState::confirmed("1.0.0".into(), v1.clone());
        store.commit_installed(&state).unwrap();
        assert!(matches!(store.installed(), Installed::Present(s) if s == state));

        // Journal round-trips and clears.
        let tx = Transaction {
            old_sha256: v1.clone(),
            new_sha256: "v2".into(),
            to_version: "2.0.0".into(),
            from_version: Some("1.0.0".into()),
        };
        store.write_journal(&tx).unwrap();
        assert_eq!(store.journal().unwrap(), Some(tx));
        store.clear_journal().unwrap();
        assert!(store.journal().unwrap().is_none());

        // Rejections round-trip.
        assert!(!store.is_rejected("v2"));
        store.reject("v2").unwrap();
        assert!(store.is_rejected("v2"));
        store.clear_rejection("v2").unwrap();
        assert!(!store.is_rejected("v2"));

        // Swap retains the previous bytes as the rollback image; verify then restore.
        std::fs::write(&paths.download, b"v2-bytes").unwrap();
        let v2 = sha256_file(&paths.download).unwrap();
        store.swap_in_staged().unwrap();
        assert_eq!(
            store.binary_sha(),
            Some(v2.clone()),
            "binary is the staged bytes"
        );
        assert_eq!(
            store.rollback_sha(),
            Some(v1.clone()),
            "previous bytes retained"
        );
        store.verify_binary(&v2).unwrap();
        assert!(
            store.verify_binary(&v1).is_err(),
            "old hash no longer matches"
        );

        store.restore_committed(&v1).unwrap();
        assert_eq!(
            store.binary_sha(),
            Some(v1.clone()),
            "restored to previous bytes"
        );
        assert!(
            store.rollback_sha().is_none(),
            "restore drops the rollback image"
        );

        // drop_rollback removes a retained rollback image.
        std::fs::write(&paths.download, b"v3-bytes").unwrap();
        store.swap_in_staged().unwrap();
        assert!(store.rollback_sha().is_some());
        store.drop_rollback();
        assert!(store.rollback_sha().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
