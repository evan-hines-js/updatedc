//! Repairing an install the node already committed to. A bundle that is committed but not
//! materialised is re-acquired from the release repository rather than treated as a fresh update.

use crate::*;

/// Repair a committed release whose bytes no longer verify on disk (bit rot, a truncated file, a
/// partially restored backup), so local corruption is recoverable instead of a permanent boot
/// crash-loop with the application stopped.
///
/// Two ordered attempts, both driven from signed evidence:
///
///  1. Re-acquire the assigned application from the same signed deployment contract normal updates
///     use. The bundle store republishes a drifted release directory over the verified tree it just
///     expanded, so this restores the ASSIGNED release — the outcome an operator wants — and it is
///     tried first for that reason. For a `file:`/absolute routing repository it makes no network
///     request at all; for every other node it is one repository access, which is exactly what the
///     caller's local verification deliberately runs *in front of*.
///  2. Failing that — an unreachable control plane, an assignment with nothing installable — fall
///     back to the predecessor the committed record already holds for exactly this purpose
///     (`rollback_guard.previous_release`, which [`garbage_collect`] keeps on disk). This needs no
///     network at all. Its bytes are verified first, so a second corrupt tree is not converged onto
///     either, and then the revert is *journaled* rather than performed: boot recovery is the one
///     rollback implementation: it compensates the failed candidate first, then moves the pointer,
///     converges and gates the predecessor. The update loop converges the node forward again from
///     there.
///
/// The corrupt archive is never *rejected*: a rejection is durable and never expires, and damage to
/// this disk is evidence about this node, not about the release — rejecting it would permanently
/// exclude a perfectly good package from every future supported route.
/// Returns the trusted repository the repair ran off, when it came from the assignment — the caller
/// reports against it without a second refresh. The predecessor fallback runs precisely when no
/// repository could be loaded, so it has none to give.
pub(crate) enum Repair {
    /// The assigned release was re-acquired and re-committed off this repository.
    FromAssignment(Box<TrustedRepository>),
    /// No signed repair was applicable, so the revert to the local predecessor is journaled and
    /// boot recovery drives it. Nothing has moved yet: the committed record still names the
    /// candidate.
    RollbackJournaled,
}

pub(crate) async fn repair_committed_bundle(
    opts: &Options,
    store: &mut Store,
) -> Result<Repair, Box<dyn std::error::Error>> {
    let assignment_error = match repair_from_assignment(opts, store).await {
        Ok(repo) => return Ok(Repair::FromAssignment(Box::new(repo))),
        Err(error) => error,
    };
    let Installed::Present(installed) = store.installed()? else {
        return Err(assignment_error);
    };
    let Some(pending) = &installed.rollback_guard else {
        return Err(assignment_error);
    };
    warn(&format!(
        "re-acquiring the assigned application failed ({assignment_error}); falling back to the \
         local predecessor {}",
        pending.previous_release.version
    ));
    // Commit to the direction only once the predecessor's own bytes verify, so an unusable
    // predecessor surfaces the original assignment error instead of journaling a revert onto a
    // second corrupt tree.
    updated::bundle::verify_release(&opts.paths.versions, &pending.previous_release).map_err(
        |error| {
            format!(
                "the local predecessor {} is not intact either: {error}",
                pending.previous_release.version
            )
        },
    )?;
    journal_predecessor_fallback(store, &installed, pending)?;
    log(&format!(
        "journaled a revert to the intact local predecessor {}; boot recovery drives it",
        pending.previous_release.version
    ));
    Ok(Repair::RollbackJournaled)
}

/// Record the revert the committed record already owes, in the one shape every other revert
/// produces, so a revert decided here and driven by boot recovery cannot describe two different
/// things. The candidate is not rejected: the same reasoning that forbids rejecting the corrupt
/// archive converges to the release whose tree this disk damaged.
pub(crate) fn journal_predecessor_fallback(
    store: &mut Store,
    installed: &updated::state::InstalledState,
    rollback_guard: &RollbackGuard,
) -> io::Result<()> {
    persist_transaction(
        store,
        &rollback_of_guarded(installed, rollback_guard, false),
    )
}

/// Re-acquire and re-commit the exact application already named by durable state. Repair shares
/// the ordinary acquisition machinery, but it is not desired-state selection: an assignment that
/// moved is handled later by the one journaled update path and cannot make this function activate a
/// new release or provider as a side effect.
pub(crate) async fn repair_from_assignment(
    opts: &Options,
    store: &mut Store,
) -> Result<TrustedRepository, Box<dyn std::error::Error>> {
    let repo = TrustedRepository::assigned(&opts.routing, &opts.storage, &opts.paths)
        .await
        .map_err(|error| format!("loading the signed repair assignment: {error}"))?;
    let Installed::Present(installed) = store.installed()? else {
        return Err("repair requires a valid committed application record".into());
    };
    // Repair only reacquires committed bytes. It never chooses an installation root or invents
    // an upgrade/downgrade route. If unavailable, journaled recovery retains its authority.
    let stance = updated_tuf::select::Stance::Reacquire {
        version: &installed.release.version,
        sha256: &installed.archive_sha256,
    };
    let request = crate::acquire::ApplicationRequest {
        repository: &repo,
        application: &opts.application,
        paths: &opts.paths,
        stance,
    };
    let selected = crate::acquire::select_assigned_application(&request, |application| {
        store.is_rejected(&installed.repository_lineage, application)
    })
    .map_err(|error| format!("preparing the signed repair: {error}"))?
    .ok_or("the signed assignment contains no installable application")?;
    let prepared = crate::acquire::prepare_assigned_application(&request, selected)
        .await
        .map_err(|error| format!("preparing the signed repair: {error}"))?;
    if prepared.release != installed.release || prepared.archive_sha256 != installed.archive_sha256
    {
        return Err(
            "authenticated repair selection did not reproduce the committed artifact".into(),
        );
    }
    // Verify-then-point, and only then commit — the same order, and for the same reason, as the
    // predecessor fallback in `repair_committed_bundle`: a failed `activate` (ENOSPC, a read-only
    // remount) must leave the committed record exactly as it found it, so the fallback still has
    // the `pending` it reads to recover.
    store.activate(&prepared.release)?;
    store.commit_installed(&installed)?;
    // Wording held stable: the e2e's offline-repair scenario asserts on this exact line, and the
    // scenario it covers — a `file:` routing repository, no network — is the one it names.
    log(&format!(
        "repaired the committed application from signed local deployment {}",
        prepared.version
    ));
    Ok(repo)
}
