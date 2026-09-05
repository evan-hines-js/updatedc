//! First-install as a first-class, journaled operation.
//!
//! Cold install has a *different meaning* than an update: there is no predecessor to roll back
//! to. It is `prepare -> place -> commit`, driven through the durable [`updated::install`] journal
//! so a crash at any boundary is completed idempotently on the next boot instead of leaving the
//! node wedged (enrollment consumed, nothing installed).
//!
//! Placement is the versioned active pointer and nothing else. Bringing the release into service
//! is the public `converge --reason install` operation, which the boot path runs once this has
//! committed.

use super::*;

use updated::install::{
    classify_install_recovery, InstallPhase, InstallRecovery, InstallTransaction,
};

/// The install boundaries chaos can crash at, as named constants. The crossings in
/// [`apply_install`]/[`place_and_commit`] and the [`INSTALL_BOUNDARIES`] list the e2e
/// enumerates both reference these, so a crossing and its list entry are the same string.
pub(crate) mod install_boundary {
    /// The install journal is durable; the release is staged but nothing is placed yet.
    pub const STARTED: &str = "install-started";
    /// The staged bytes are recorded as prepared.
    pub const PREPARED: &str = "install-prepared";
    /// The active pointer references the release and the provider's placement has run.
    pub const PLACED: &str = "install-placed";
    /// Enrollment and the installed record are written; only journal cleanup remains.
    pub const COMMITTED: &str = "install-committed";
}

/// The ordered install boundary list, emitted by `agent --list-install-chaos-boundaries`
/// so the e2e crashes at exactly the crossings the install machine defines.
#[cfg(any(feature = "chaos", test))]
pub(crate) const INSTALL_BOUNDARIES: &[&str] = &[
    install_boundary::STARTED,
    install_boundary::PREPARED,
    install_boundary::PLACED,
    install_boundary::COMMITTED,
];

fn advance_install(
    store: &mut Store,
    tx: &mut InstallTransaction,
    next: InstallPhase,
) -> io::Result<()> {
    tx.advance(next)?;
    store.write_install_journal(tx)
}

/// Ensure a committed application exists, returning whether this boot performed the install
/// (so the caller selects the boot converge's `install` reason instead of `restart`).
///
/// An in-flight install journal is reconciled first: a committed-but-uncleared install just
/// clears it, an interrupted one is driven to completion from its recorded phase — either way
/// the app has not launched yet, so both count as this boot performing the first install. Only
/// then is a genuinely empty node cold-installed. The old "enrollment consumed but nothing
/// installed" dead end is gone — that state is now a recoverable journal, not a brick.
///
/// Safety of the interaction with the update state machine rests on one invariant this
/// function upholds: it runs before the boot/update recovery ([`gather_situation`] +
/// [`execute_update`]) and, on `Ok`, always leaves *no* install journal on disk (on `Err` the
/// boot never proceeds). So the two journals are temporally disjoint: the install journal exists
/// on an empty node or while descending from a rejected provisional head, always with no update
/// journal; the update journal exists only after a confirmed install. During fallback the old
/// record remains authoritative until the new install commits. Neither machine ever reads the
/// other's journal.
pub(crate) async fn ensure_installed(
    opts: &Options,
    store: &mut Store,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(tx) = store.install_journal()? {
        let installed = match store.installed()? {
            updated::state::Installed::Present(state) => Some(state),
            _ => None,
        };
        match classify_install_recovery(&tx, installed.as_deref()) {
            // The install committed but crashed before clearing its journal — the app never
            // launched. Clearing it is the last install step, so this boot still owns the first
            // install: report it as such so the boot converge runs with `reason=install`.
            InstallRecovery::Committed => {
                // The installed record was already committed *provisional* by `place_and_commit`;
                // clearing the journal is the last install step. The head still hasn't launched,
                // so recovery from here is identical to a fresh cold install.
                store.clear_install_journal()?;
                return Ok(true);
            }
            InstallRecovery::Resume => {
                warn(&format!(
                    "resuming an interrupted first install of {} from its journal",
                    tx.release.version
                ));
                place_and_commit(opts, store, tx).await?;
                return Ok(true);
            }
        }
    }

    match (
        store.installed()?,
        updated::state::read_install_history(&opts.paths.installed),
    ) {
        (updated::state::Installed::Missing, updated::state::InstallHistory::Missing) => {
            apply_install(opts, store).await?;
            Ok(true)
        }
        (updated::state::Installed::Missing, _) => Err(
            "installed state is missing after a previous installation with no recoverable install journal; refusing to cold-install"
                .into(),
        ),
        (updated::state::Installed::Present(state), updated::state::InstallHistory::Present) => {
            // A *provisional* head (`confirmed == false`, never passed a health gate) that has
            // been rejected must not be relaunched into a crash loop. This is the first-install
            // case: a fresh node cold-installs its (broken) assigned head, the boot rejects it on
            // crash/wedge, and it restarts. Re-run the cold install so cold-install fallback descends
            // past the rejected head to the newest healthy release. (Storage is persistent, so this
            // only ever happens during a node's initial install, never a mid-life state loss.)
            //
            // The `confirmed` gate is load-bearing: a *confirmed* head that a normal update/rollback
            // later rejects is recovered by the update state machine (its journal restores the
            // predecessor). Re-installing there would preempt that recovery and strand the node. So
            // defer whenever the head has proven healthy, or an update transaction is mid-flight.
            if !state.is_proven()
                && store.journal()?.is_none()
                && store.rejects_deployment(&state.repository_lineage, &state.archive_sha256)
            {
                warn(&format!(
                    "provisional head {} is rejected; re-installing so cold-install fallback descends past it",
                    state.release.version
                ));
                apply_install(opts, store).await?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        (updated::state::Installed::Present(_), _) => {
            Err("installed state exists without a valid enrollment record".into())
        }
        (updated::state::Installed::Invalid, _) => {
            Err("installed state is invalid; refusing to cold-install".into())
        }
    }
}

/// Resolve the first trusted assignment, stage the payload and its reconciler,
/// then drive the durable install to a committed, cleared journal.
async fn apply_install(
    opts: &Options,
    store: &mut Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo = TrustedRepository::assigned(&opts.routing, &opts.storage, &opts.paths)
        .await
        .map_err(|error| format!("loading the first trusted assignment: {error}"))?;
    let assignment = repo
        .assignment_context()
        .ok_or("the first trusted repository has no desired deployment")?;
    let lineage = assignment.repository_lineage().clone();
    // Resolve, download and verify the first application, descending past any *malformed* bundle
    // inline. A malformed head (corrupt archive, bad manifest, bad/missing entrypoint) passes its
    // signed archive sha but fails to extract/validate — the update path rejects it and moves on
    // (see `check_application`), and cold install must do the same or a first-install node stalls
    // forever re-downloading a bundle it can never install. Each iteration rejects one malformed
    // head and re-selects, so cold-install fallback monotonically descends to the newest *installable*
    // release; the loop terminates when one installs or nothing selectable remains.
    let (prepared, providers) = loop {
        let request = crate::acquire::ApplicationRequest {
            repository: &repo,
            application: &opts.application,
            paths: &opts.paths,
            // A cold install: nothing is on this node, so there is no floor and a signed
            // `coldInstallFallback` may descend. The one stance that permits a descent.
            stance: updated_tuf::select::Stance::Nothing,
        };
        let selected = match crate::acquire::select_assigned_application(
            &request,
            |application_sha256| store.rejects_deployment(&lineage, application_sha256),
        ) {
            Ok(Some(selected)) => selected,
            Ok(None) => {
                // Enumerate exactly what the repository offered and why nothing was selectable, so
                // an empty cold-install-fallback descent is diagnosable rather than opaque. Rejection
                // is never-retry evidence: there is no availability exception that may relaunch
                // already-rejected bytes, even when this node previously committed them.
                let policy = updated_tuf::DefaultPolicy::current(
                    &opts.application.product,
                    &opts.application.channel,
                );
                let diagnostics = repo.selection_diagnostics(
                    &policy,
                    updated_tuf::select::Stance::Nothing,
                    |application_sha256| store.rejects_deployment(&lineage, application_sha256),
                );
                return Err(format!(
                    "the first trusted assignment contains no installable application; cold-install \
                     fallback found nothing selectable at or below the assigned head:\n{diagnostics}"
                )
                .into());
            }
            // A failure to read the signed metadata at all says nothing about any release, so
            // nothing is rejected: the boot retries the whole cold install later.
            Err(error) => return Err(format!("preparing the first application: {error}").into()),
        };
        match crate::acquire::prepare_assigned_application(&request, selected).await {
            Ok(prepared) => {
                let execution = prepared.reconciler.clone();
                break (prepared, execution);
            }
            Err(error) => {
                // A malformed bundle carries a rejectable archive hash; reject it and descend. A
                // transport error (e.g. a download sha mismatch) carries none, so it propagates and
                // the boot retries it later rather than treating a transient fetch as a bad release.
                if let Some((version, archive_sha256)) = error.rejected_archive() {
                    warn(&format!(
                        "first-install bundle {version} is malformed; rejecting it so cold-install \
                         fallback descends past it ({error})"
                    ));
                    store.reject_artifact(&lineage, archive_sha256)?;
                    continue;
                }
                return Err(format!("preparing the first application: {error}").into());
            }
        }
    };

    // The application bytes are staged. From the journal write on, a crash is completed by
    // recovery rather than reinterpreted as a never-enrolled node.
    let mut tx = InstallTransaction {
        id: updated::rand::token()?,
        release: prepared.release.clone(),
        archive_sha256: prepared.archive_sha256.clone(),
        repository_lineage: lineage,
        reconciler: Box::new(providers),
        phase: InstallPhase::Started,
    };
    let chaos = Chaos::from_env();
    store.write_install_journal(&tx)?;
    chaos.crossing(install_boundary::STARTED);
    advance_install(store, &mut tx, InstallPhase::Prepared)?;
    chaos.crossing(install_boundary::PREPARED);
    place_and_commit(opts, store, tx).await?;
    Ok(())
}

/// Drive an install from its current journaled phase to a committed, cleared state. Every step
/// is idempotent, so a resumed install re-runs its remaining steps safely: the pointer write is
/// atomic, the provider placement is idempotent, and enrollment + commit are one-way writes.
async fn place_and_commit(
    opts: &Options,
    store: &mut Store,
    mut tx: InstallTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    let chaos = Chaos::from_env();
    // A resume that lands before the staged bytes were recorded still has them on disk (staging
    // precedes the journal), so it is safe to treat as prepared and proceed to placement.
    if tx.phase == InstallPhase::Started {
        advance_install(store, &mut tx, InstallPhase::Prepared)?;
    }

    // Place: point the active release at the staged bytes. Any operator first-install setup runs
    // later, in the reconciler's `converge` on the first launch (`reason=install`).
    store.activate(&tx.release)?;
    if tx.phase == InstallPhase::Prepared {
        advance_install(store, &mut tx, InstallPhase::Placed)?;
    }
    chaos.crossing(install_boundary::PLACED);

    // Commit: consume enrollment first (so a later interrupted write fails closed), then write
    // the authoritative installed record, record the terminal phase, and clear the journal.
    // Enrollment is one-way (`create_new`); a resume that already consumed it skips this.
    if matches!(
        updated::state::read_install_history(&opts.paths.installed),
        updated::state::InstallHistory::Missing
    ) {
        updated::state::record_first_install(&opts.paths.installed)?;
    }
    // Commit the head *provisional*: it has never launched, let alone proven healthy. If it turns
    // out to be a broken assigned head (crashes or wedges before its first passing gate) the boot
    // rejects it from this record and cold-install fallback descends past it; the first passing health
    // gate flips it to confirmed.
    store.commit_installed(&updated::state::InstalledState::provisional(
        tx.repository_lineage.clone(),
        tx.release.clone(),
        tx.archive_sha256.clone(),
        tx.reconciler.clone(),
    ))?;
    // A valid but machine-inconsistent terminal journal can only come from external corruption,
    // not [`Store::write_install_journal`]. Still converge it: recommit the exact unit above, then
    // retain its already-terminal phase instead of attempting an impossible self-transition.
    if tx.phase == InstallPhase::Placed {
        advance_install(store, &mut tx, InstallPhase::Committed)?;
    }
    chaos.crossing(install_boundary::COMMITTED);
    store.clear_install_journal()?;
    log(&format!(
        "cold-installed application {} from the first trusted assignment",
        tx.release.version
    ));
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn install_boundaries_are_unique_and_one_per_phase() {
        assert_eq!(
            INSTALL_BOUNDARIES.len(),
            INSTALL_BOUNDARIES.iter().collect::<HashSet<_>>().len(),
            "install chaos boundaries must be distinct"
        );
        // One crossable boundary per journaled phase: a crash at each is recoverable.
        assert_eq!(
            INSTALL_BOUNDARIES,
            &[
                install_boundary::STARTED,
                install_boundary::PREPARED,
                install_boundary::PLACED,
                install_boundary::COMMITTED,
            ]
        );
    }
}
