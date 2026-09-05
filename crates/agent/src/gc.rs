//! Reclaiming disk from releases the node no longer needs, without touching the active release
//! or any output snapshot a rollback could still need.

use crate::*;

pub(crate) fn garbage_collect(opts: &Options, store: &Store) {
    let installed = match store.installed() {
        Ok(Installed::Present(installed)) => installed,
        Ok(Installed::Missing | Installed::Invalid) => return,
        Err(error) => {
            warn(&format!(
                "garbage collection skipped because installed state could not be read: {error}"
            ));
            return;
        }
    };
    let mut releases = vec![installed.release.clone()];
    // No transaction or confirmation guard can still consume this pin. The current cache is
    // retained for ordinary offline boot; obsolete transaction credentials are removed.
    if installed.rollback_guard.is_none() && matches!(store.journal(), Ok(None)) {
        if let Err(error) = foundation::durable::remove_path(&opts.paths.recovery_inputs) {
            warn(&format!("removing settled recovery inputs failed: {error}"));
        }
    }
    let output_snapshots = protected_output_snapshot_manifests(&installed);
    if let Some(pending) = installed.rollback_guard {
        releases.push(pending.previous_release);
    }
    match updated::gc::prune_releases(
        &opts.paths.versions,
        &releases,
        opts.storage.inactive_releases,
        opts.storage.inactive_bytes,
    ) {
        Ok(removed) if removed != 0 => {
            log(&format!("removed {removed} inactive application releases"))
        }
        Ok(_) => {}
        Err(error) => warn(&format!(
            "garbage collecting application releases failed: {error}"
        )),
    }
    match updated::reconciler::prune_output_snapshots(&opts.paths, &output_snapshots) {
        Ok(removed) if removed != 0 => log(&format!(
            "removed {removed} stale reconciler output snapshots"
        )),
        Ok(_) => {}
        Err(error) => warn(&format!(
            "garbage collecting reconciler output snapshots failed: {error}"
        )),
    }
}

/// The one identity rule for reconciler output retention.
///
/// Snapshots are written and read by release manifest digest because that is the release identity
/// available to every reconciler invocation. Archive digests deliberately do not participate here:
/// protecting them would retain paths no writer creates and delete the active snapshot whenever
/// the archive and manifest digests differ (which is the ordinary case).
pub(crate) fn protected_output_snapshot_manifests(
    installed: &updated::state::InstalledState,
) -> Vec<String> {
    let mut manifests = vec![installed.release.manifest_sha256.clone()];
    if let Some(pending) = &installed.rollback_guard {
        manifests.push(pending.previous_release.manifest_sha256.clone());
    }
    manifests
}
