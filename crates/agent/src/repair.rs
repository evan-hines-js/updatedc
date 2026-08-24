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
///     (`pending.previous_release`, which [`garbage_collect`] keeps on disk). This needs no
///     network at all. Its bytes are verified first, so a second corrupt tree is not converged onto
///     either, and then the revert is *journaled* rather than performed: boot recovery is the one
///     rollback implementation, and it is what moves the pointer, runs the predecessor's `apply`,
///     gates it, and replays the candidate's compensating `rollback`. The update loop converges the
///     node forward again from there.
///
/// The corrupt archive is never *rejected*: a rejection is durable and never expires, and damage to
/// this disk is evidence about this node, not about the release — rejecting it would permanently
/// exclude a perfectly good version from this node and walk its ordered fallback downward.
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
    store: &mut FileStore,
) -> Result<Repair, Box<dyn std::error::Error>> {
    let assignment_error = match repair_from_assignment(opts, store).await {
        Ok(repo) => return Ok(Repair::FromAssignment(Box::new(repo))),
        Err(error) => error,
    };
    let Installed::Present(installed) = store.installed() else {
        return Err(assignment_error);
    };
    let Some(pending) = &installed.pending else {
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
/// archive applies to the release whose tree this disk damaged.
pub(crate) fn journal_predecessor_fallback(
    store: &mut dyn Store,
    installed: &updated::state::InstalledState,
    pending: &Pending,
) -> io::Result<()> {
    persist_transaction(store, &rollback_of_unconfirmed(installed, pending, false))
}

/// Re-acquire and re-commit the assigned application from the signed deployment contract. This is
/// the ordinary update machinery's `prepare` step run for repair: the release is re-downloaded and
/// re-materialized, which republishes the drifted tree.
pub(crate) async fn repair_from_assignment(
    opts: &Options,
    store: &mut FileStore,
) -> Result<TrustedRepository, Box<dyn std::error::Error>> {
    let repo = TrustedRepository::assigned(&opts.routing, &opts.storage, &opts.paths)
        .await
        .map_err(|error| format!("loading the signed repair assignment: {error}"))?;
    let assignment = repo
        .assignment()
        .ok_or("the signed repository has no desired deployment")?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    // A repair re-acquires the release this node is ALREADY committed to, so it must lift the
    // selector's "you already have that version, nothing to do" short-circuit — and nothing else.
    // It used to say `None`, which the selector reads as "nothing is installed": that is the one
    // stance a signed `orderedInstallFallback` descends under, so a repair on a node whose
    // assigned head was rejected walked down to an older release and installed it, past the
    // anti-rollback floor the ordinary update path refuses to cross. `Reacquire` keeps the floor
    // and keeps the exact-pin branch; if the assigned head really is unselectable the repair fails
    // here and `repair_committed_bundle` falls back to the journaled predecessor revert, which is
    // a rollback this node has evidence for rather than a silent downgrade.
    let installed = store.installed();
    let stance = match &installed {
        Installed::Present(state) => state
            .version_floor_for(&lineage)
            .map_or(updated_tuf::select::Stance::Nothing, |version| {
                updated_tuf::select::Stance::Reacquire(version)
            }),
        Installed::Missing | Installed::Invalid => updated_tuf::select::Stance::Nothing,
    };
    let request = crate::acquire::ApplicationRequest {
        repository: &repo,
        application: &opts.application,
        paths: &opts.paths,
        stance,
    };
    let selected = crate::acquire::select_assigned_application(&request, |sha256| {
        store.is_rejected(&lineage, sha256)
    })
    .map_err(|error| format!("preparing the signed repair: {error}"))?
    .ok_or("the signed assignment contains no installable application")?;
    // The set signed into the version just selected, decided once with it.
    let version_provider_set = selected.provider_set.clone();
    let prepared = crate::acquire::prepare_assigned_application(&request, selected)
        .await
        .map_err(|error| format!("preparing the signed repair: {error}"))?;
    let providers = selection::stage_providers(opts, &repo, store, version_provider_set.as_ref())
        .await
        .map_err(|error| format!("staging the providers for the repair: {error}"))?;
    // A repair replaces drifted BYTES; it does not decide an in-flight update. When it lands back
    // on the release the record already names, the record's rollback intent and its provisional
    // flag are carried through unchanged: erasing them would silently confirm an unconfirmed head —
    // nothing left for `plan_boot` to revert on the next crash, and `garbage_collect` free to prune
    // the very predecessor this function's own fallback depends on. A repair that lands on a
    // different head (the assignment moved on) is a head this node has never launched, let alone
    // health-gated, so it is committed provisional exactly as a cold install commits one — ordered
    // fallback has to be able to descend past it if it turns out to be broken.
    let (pending, confirmed) = match store.installed() {
        Installed::Present(state) if state.release == prepared.release => {
            (state.pending, state.confirmed)
        }
        _ => (None, false),
    };
    // Verify-then-point, and only then commit — the same order, and for the same reason, as the
    // predecessor fallback in `repair_committed_bundle`: a failed `activate` (ENOSPC, a read-only
    // remount) must leave the committed record exactly as it found it, so the fallback still has
    // the `pending` it reads to recover.
    store.activate(&prepared.release)?;
    store.commit_installed(&updated::state::InstalledState {
        repository_lineage: lineage,
        release: prepared.release.clone(),
        archive_sha256: prepared.archive_sha256,
        lifecycle: Box::new(providers),
        pending,
        confirmed,
    })?;
    // Wording held stable: the e2e's offline-repair scenario asserts on this exact line, and the
    // scenario it covers — a `file:` routing repository, no network — is the one it names.
    log(&format!(
        "repaired the committed application from signed local deployment {}",
        prepared.version
    ));
    Ok(repo)
}
