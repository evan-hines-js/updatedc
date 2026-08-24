//! Reclaiming disk from releases the node no longer needs, without touching the active release
//! or any output snapshot a rollback could still need.

use crate::*;

pub(crate) fn garbage_collect(opts: &Options, store: &dyn Store) {
    let Installed::Present(installed) = store.installed() else {
        return;
    };
    let mut releases = vec![installed.release.clone()];
    let mut providers = Vec::new();
    let output_snapshots = protected_output_snapshot_manifests(&installed);
    // Protect the installed release's own providers — they run on every boot (pre-start,
    // verification) — and the pending predecessor's, which a rollback would replay.
    providers.push(installed.lifecycle.release);
    if let Some(pending) = installed.pending {
        releases.push(pending.previous_release);
        providers.push(pending.lifecycle.release);
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
    match updated::gc::prune_releases(
        &opts.paths.provider_versions,
        &providers,
        opts.storage.inactive_providers,
        opts.storage.inactive_bytes,
    ) {
        Ok(removed) if removed != 0 => {
            log(&format!("removed {removed} inactive lifecycle providers"))
        }
        Ok(_) => {}
        Err(error) => warn(&format!(
            "garbage collecting lifecycle providers failed: {error}"
        )),
    }
    // A release's writable working directory lives outside its content-addressed tree — the tree is
    // re-hashed on every check, so an application writing to its own `cwd` would condemn it — which
    // means pruning the tree does not take the scratch with it. Reap here, in the same pass, rather
    // than leaving it to whenever the node next resolves a release for launch.
    updated::gc::reap_orphaned_workspaces(&opts.paths.work, &opts.paths.versions);
    updated::gc::reap_orphaned_workspaces(&opts.paths.provider_work, &opts.paths.provider_versions);
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
/// available to every lifecycle invocation. Archive digests deliberately do not participate here:
/// protecting them would retain paths no writer creates and delete the active snapshot whenever
/// the archive and manifest digests differ (which is the ordinary case).
pub(crate) fn protected_output_snapshot_manifests(
    installed: &updated::state::InstalledState,
) -> Vec<String> {
    let mut manifests = vec![installed.release.manifest_sha256.clone()];
    if let Some(pending) = &installed.pending {
        manifests.push(pending.previous_release.manifest_sha256.clone());
    }
    manifests
}
