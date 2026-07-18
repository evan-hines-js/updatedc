//! The single durable activation and recovery path for update-before-launch clients.

use std::io;

use crate::bundle::{read_active, write_active, ReleaseId};
use crate::config::Paths;
use crate::provider::BundleStore;
use crate::state::{read_installed, write_installed, Installed, InstalledState};
use crate::transaction::{self, Kind, Phase, Recovery, Transaction};

/// Atomically activate and commit an already installed, verified release.
pub fn activate(
    paths: &Paths,
    installed: &InstalledState,
    candidate: ReleaseId,
    candidate_archive_sha256: String,
) -> io::Result<()> {
    let mut transaction = Transaction {
        id: crate::rand::token()?,
        kind: Kind::OnLaunch,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.clone(),
        candidate_rejection_required: false,
        lifecycle: None,
        phase: Phase::Started,
    };
    transaction::write(&paths.journal, &transaction)?;
    write_active(&paths.active_release, &candidate)?;
    advance(paths, &mut transaction, Phase::CandidateActivated)?;

    BundleStore::for_app(paths).resolve(&candidate)?;
    advance(paths, &mut transaction, Phase::CandidateVerified)?;
    write_installed(
        &paths.state,
        &InstalledState::confirmed(candidate, candidate_archive_sha256),
    )?;
    advance(paths, &mut transaction, Phase::Committed)?;
    transaction::clear(&paths.journal)
}

/// Reconcile an interrupted update-before-launch activation before selecting new work.
pub fn reconcile(paths: &Paths) -> io::Result<()> {
    let Some(transaction) = transaction::read(&paths.journal)? else {
        return Ok(());
    };
    let active = read_active(&paths.active_release)?;
    let committed = match read_installed(&paths.state) {
        Installed::Present(state) => Some(state.release),
        Installed::Missing | Installed::Invalid => None,
    };
    if transaction::classify_recovery(&transaction, active.as_ref(), committed.as_ref())
        == Recovery::RestorePredecessor
    {
        BundleStore::for_app(paths).resolve(&transaction.previous_release)?;
        write_active(&paths.active_release, &transaction.previous_release)?;
    }
    transaction::clear(&paths.journal)
}

fn advance(paths: &Paths, transaction: &mut Transaction, phase: Phase) -> io::Result<()> {
    transaction.advance(phase).map_err(io::Error::other)?;
    transaction::write(&paths.journal, transaction)
}
