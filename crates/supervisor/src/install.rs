//! First-install as a first-class, journaled operation.
//!
//! Cold install has a *different meaning* than an update: there is no predecessor to drain,
//! stop, or roll back to. It is `prepare -> place -> commit`, driven through the durable
//! [`updated::install`] journal so a crash at any boundary is completed idempotently on the
//! next boot instead of leaving the node wedged (enrollment consumed, nothing installed).
//!
//! Placement is uniform across every mode: the versioned active pointer places the release, and
//! the app is launched fresh. Any first-install setup a deployment needs (seed a directory, start
//! a systemd unit) runs in the lifecycle `pre-start` hook with `reason=install` on the first
//! launch — there is no separate install-time provider seam.

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

/// The ordered install boundary list, emitted by `supervisor --list-install-chaos-boundaries`
/// so the e2e crashes at exactly the crossings the install machine defines.
#[cfg(any(feature = "chaos", test))]
pub(crate) const INSTALL_BOUNDARIES: &[&str] = &[
    install_boundary::STARTED,
    install_boundary::PREPARED,
    install_boundary::PLACED,
    install_boundary::COMMITTED,
];

fn advance_install(
    store: &mut FileStore,
    tx: &mut InstallTransaction,
    next: InstallPhase,
) -> io::Result<()> {
    tx.advance(next)?;
    store.write_install_journal(tx)
}

/// Ensure a committed application exists, returning whether this boot performed the install
/// (so the caller selects the `install` pre-start reason instead of `restart`).
///
/// An in-flight install journal is reconciled first: a committed-but-uncleared install just
/// clears it, an interrupted one is driven to completion from its recorded phase — either way
/// the app has not launched yet, so both count as this boot performing the first install. Only
/// then is a genuinely empty node cold-installed. The old "enrollment consumed but nothing
/// installed" dead end is gone — that state is now a recoverable journal, not a brick.
///
/// Safety of the interaction with the update state machine rests on one invariant this
/// function upholds: it runs before the boot/update recovery ([`gather_situation`] +
/// [`apply_update`]) and, on `Ok`, always leaves *no* install journal on disk (on `Err` the
/// boot never proceeds). So the two journals are temporally disjoint — the install journal
/// exists only before the first commit (installed absent), the update journal only after
/// (`apply_update` requires an installed release) — and the update machine never observes an
/// install in flight. They live in separate files and are never read by each other's machine.
pub(crate) async fn ensure_installed(
    opts: &Options,
    store: &mut FileStore,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(tx) = store.install_journal()? {
        let installed = match store.installed() {
            updated::state::Installed::Present(state) => Some(state.release.clone()),
            _ => None,
        };
        match classify_install_recovery(&tx, installed.as_ref()) {
            // The install committed but crashed before clearing its journal — the app never
            // launched. Clearing it is the last install step, so this boot still owns the first
            // install: report it as such so pre-start runs with `reason=install`, not `restart`.
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
        store.installed(),
        updated::state::read_enrollment(&opts.paths.state),
    ) {
        (updated::state::Installed::Missing, updated::state::EnrollmentState::Missing) => {
            match apply_install(opts, store).await? {
                ColdInstall::Installed => Ok(true),
                // A truly fresh node with nothing installable at or below the assigned head has
                // no committed release to fall back to — this is genuinely fatal.
                ColdInstall::NothingSelectable(diagnostics) => Err(format!(
                    "the first trusted assignment contains no installable application; ordered \
                     fallback found nothing selectable at or below the assigned head:\n{diagnostics}"
                )
                .into()),
            }
        }
        (updated::state::Installed::Missing, _) => Err(
            "installed state is missing after enrollment with no recoverable install journal; refusing to cold-install"
                .into(),
        ),
        (updated::state::Installed::Present(state), updated::state::EnrollmentState::Present) => {
            // A *provisional* head (`confirmed == false`, never passed a health gate) that has
            // been rejected must not be relaunched into a crash loop. This is the first-install
            // case: a fresh node cold-installs its (broken) assigned head, the boot rejects it on
            // crash/wedge, and it restarts. Re-run the cold install so ordered fallback descends
            // past the rejected head to the newest healthy release. (Storage is persistent, so this
            // only ever happens during a node's initial install, never a mid-life state loss.)
            //
            // The `confirmed` gate is load-bearing: a *confirmed* head that a normal update/rollback
            // later rejects is recovered by the update state machine (its journal restores the
            // predecessor). Re-installing there would preempt that recovery and strand the node. So
            // defer whenever the head has proven healthy, or an update transaction is mid-flight.
            if !state.confirmed
                && store.journal()?.is_none()
                && store.is_rejected(&state.repository_lineage, &state.archive_sha256)
            {
                warn(&format!(
                    "provisional head {} is rejected; re-installing so ordered fallback descends past it",
                    state.release.version
                ));
                match apply_install(opts, store).await? {
                    ColdInstall::Installed => Ok(true),
                    // Fail open: nothing is installable at or below the assigned head, but this
                    // release is already committed on disk. Bricking (exit fatal → guardian
                    // crash-loop) is never better than relaunching a release we already committed
                    // and verified — hold it and keep serving; it confirms on a passing gate. This
                    // is a first-install node whose only healthy floor was transiently rejected
                    // (e.g. a slow first-boot gate under load): it must recover, not strand.
                    ColdInstall::NothingSelectable(diagnostics) => {
                        warn(&format!(
                            "ordered fallback found nothing selectable below the rejected head; \
                             holding the committed {} rather than bricking the node:\n{diagnostics}",
                            state.release.version
                        ));
                        Ok(false)
                    }
                }
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

/// The result of a cold install attempt.
enum ColdInstall {
    /// A selectable release was staged and committed (provisional).
    Installed,
    /// Ordered fallback found nothing installable at or below the assigned head — the descent
    /// emptied out. Carries the selection diagnostics. The caller decides whether that is fatal
    /// (a fresh node with nothing at all to run) or survivable (a node already holding a committed
    /// release it can keep serving instead of bricking).
    NothingSelectable(String),
}

/// Resolve the first trusted assignment, stage the application and its lifecycle provider,
/// then drive the durable install to a committed, cleared journal.
async fn apply_install(
    opts: &Options,
    store: &mut FileStore,
) -> Result<ColdInstall, Box<dyn std::error::Error>> {
    let repo =
        TrustedRepository::assigned(&opts.routing, &opts.repository, &opts.storage, &opts.paths)
            .await
            .map_err(|error| format!("loading the first trusted assignment: {error}"))?;
    let assignment = repo
        .assignment()
        .ok_or("the first trusted repository has no desired deployment")?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    // Resolve, download and verify the first application, descending past any *malformed* bundle
    // inline. A malformed head (corrupt archive, bad manifest, bad/missing entrypoint) passes its
    // signed archive sha but fails to extract/validate — the update path rejects it and moves on
    // (see `check_application`), and cold install must do the same or a first-install node stalls
    // forever re-downloading a bundle it can never install. Each iteration rejects one malformed
    // head and re-selects, so ordered fallback monotonically descends to the newest *installable*
    // release; the loop terminates when one installs or nothing selectable remains.
    let (prepared, providers) = loop {
        match update_client::prepare_assigned_application(
            update_client::ApplicationRequest {
                repository: &repo,
                application: &opts.application,
                repository_config: &opts.repository,
                paths: &opts.paths,
                current_version: None,
            },
            |sha256| store.is_rejected(&lineage, sha256),
        )
        .await
        {
            Ok(Some(prepared)) => {
                // Stage the operator's providers *for this app version* — its own signed provider
                // set governs (app + providers are one signed rollback unit, see `stage_providers`).
                // A corrupt or previously-rejected provider set makes this whole version
                // uninstallable: reject the app version so ordered fallback descends to one whose
                // provider set is good, rather than crash-looping on a version we can never bring up.
                match stage_providers(opts, &repo, store, None).await {
                    Ok(providers) => break (prepared, providers),
                    Err(error) => {
                        warn(&format!(
                            "first-install provider set for {} is unusable ({error}); rejecting \
                             this version so ordered fallback descends to one with a good set",
                            prepared.version
                        ));
                        store.reject(&lineage, &prepared.archive_sha256)?;
                        continue;
                    }
                }
            }
            Ok(None) => {
                // Enumerate exactly what the repository offered and why nothing was selectable, so
                // an empty ordered-fallback descent is diagnosable from the log, not opaque. The
                // caller decides whether an empty descent is fatal or survivable.
                let policy = updated_tuf::DefaultPolicy::current(
                    &opts.application.product,
                    &opts.application.channel,
                );
                return Ok(ColdInstall::NothingSelectable(repo.selection_diagnostics(
                    &policy,
                    None,
                    |sha| store.is_rejected(&lineage, sha),
                )));
            }
            Err(error) => {
                // A malformed bundle carries a rejectable archive hash; reject it and descend. A
                // transport error (e.g. a download sha mismatch) carries none, so it propagates and
                // the boot retries it later rather than treating a transient fetch as a bad release.
                if let Some((version, archive_sha256)) = error.rejected_archive() {
                    warn(&format!(
                        "first-install bundle {version} is malformed; rejecting it so ordered \
                         fallback descends past it ({error})"
                    ));
                    store.reject(&lineage, archive_sha256)?;
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
        lifecycle: providers.lifecycle.map(Box::new),
        healthcheck: providers.healthcheck.map(Box::new),
        phase: InstallPhase::Started,
    };
    let chaos = Chaos::from_env();
    store.write_install_journal(&tx)?;
    chaos.crossing(install_boundary::STARTED);
    advance_install(store, &mut tx, InstallPhase::Prepared)?;
    chaos.crossing(install_boundary::PREPARED);
    place_and_commit(opts, store, tx).await?;
    Ok(ColdInstall::Installed)
}

/// Drive an install from its current journaled phase to a committed, cleared state. Every step
/// is idempotent, so a resumed install re-runs its remaining steps safely: the pointer write is
/// atomic, the provider placement is idempotent, and enrollment + commit are one-way writes.
async fn place_and_commit(
    opts: &Options,
    store: &mut FileStore,
    mut tx: InstallTransaction,
) -> Result<(), Box<dyn std::error::Error>> {
    let chaos = Chaos::from_env();
    // A resume that lands before the staged bytes were recorded still has them on disk (staging
    // precedes the journal), so it is safe to treat as prepared and proceed to placement.
    if tx.phase == InstallPhase::Started {
        advance_install(store, &mut tx, InstallPhase::Prepared)?;
    }

    // Place: point the active release at the staged bytes. Any operator first-install setup runs
    // later, in the `pre-start` hook on the first launch (`reason=install`).
    store.activate(&tx.release)?;
    if tx.phase == InstallPhase::Prepared {
        advance_install(store, &mut tx, InstallPhase::Placed)?;
    }
    chaos.crossing(install_boundary::PLACED);

    // Commit: consume enrollment first (so a later interrupted write fails closed), then write
    // the authoritative installed record, record the terminal phase, and clear the journal.
    // Enrollment is one-way (`create_new`); a resume that already consumed it skips this.
    if matches!(
        updated::state::read_enrollment(&opts.paths.state),
        updated::state::EnrollmentState::Missing
    ) {
        updated::state::enroll(&opts.paths.state, tx.repository_lineage.clone())?;
    }
    // Commit the head *provisional*: it has never launched, let alone proven healthy. If it turns
    // out to be a broken assigned head (crashes or wedges before its first passing gate) the boot
    // rejects it from this record and ordered fallback descends past it; the first passing health
    // gate flips it to confirmed.
    store.commit_installed(
        &updated::state::InstalledState::provisional(
            tx.repository_lineage.clone(),
            tx.release.clone(),
            tx.archive_sha256.clone(),
        )
        .with_lifecycle(tx.lifecycle.clone())
        .with_healthcheck(tx.healthcheck.clone()),
    )?;
    advance_install(store, &mut tx, InstallPhase::Committed)?;
    chaos.crossing(install_boundary::COMMITTED);
    store.clear_install_journal()?;
    log(&format!(
        "cold-installed application {} from the first trusted assignment",
        tx.release.version
    ));
    Ok(())
}

#[cfg(test)]
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
