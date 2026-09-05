use super::super::*;
use updated_contracts::reconciler::{attempt, Operation};

/// The never-healthy twin of `cold_install_descends_past_broken_head`. There the assigned heads
/// fail their `converge`; here `converge` succeeds — the workload starts and stays alive — but the
/// release never becomes healthy, so its `healthcheck` never passes. The node must reject each such
/// head and descend, and the workload each rejected head left running must be stopped by the hook
/// that replaces it: a descent that left the wedged process holding the service address would
/// health-gate the stale process and reject the healthy release it had just installed.
pub(crate) fn cold_install_descends_past_unhealthy_head(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21330", "127.0.0.1:21331");
    let dir = ctx.work.join("cold-install-wedge");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    // The healthy release below the wedged heads.
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Two "wedged" heads: an entrypoint that stays alive but binds nothing, so `converge` succeeds and
    // the health gate fails forever. The assigned head is the newest (3.0.0), so recovery must stop
    // and descend past both 3.0.0 and 2.0.0 to reach the healthy 1.0.0.
    let wedged = dir.join("wedged-app");
    std::fs::write(&wedged, b"#!/bin/sh\nexec sleep 100000\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &wedged)?;
    ctx.publish(&dir, "app", "3.0.0", &wedged)?;
    let _server = ctx.serve(&dir, srv)?;
    let command = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .cold_install_fallback()
        .workload(svc)
        .check_interval("1s")
        // A short grace keeps the per-head wedge detection quick; the head never becomes healthy,
        // so the gate fails after the grace and the boot rejects it and descends.
        .health_grace("3s")
        .command()?;
    let node = Service::spawn("cold-install-wedge", &command);
    // Catch the wedged head's own process while it is running, so the descent can be shown to have
    // ended it rather than merely to have installed something else.
    let wedged_pid = wait_until(CONVERGE_TIMEOUT, || fixture::workload_pid(&dir).is_some())
        .then(|| fixture::workload_pid(&dir))
        .flatten()
        .ok_or("the wedged head's converge never started a workload")?;
    // Recovery is proven only when the healthy 1.0.0 actually serves.
    if !wait_for_version(svc, "1.0.0", CONVERGE_TIMEOUT) {
        let log = node.captured_log();
        return fail(format!(
            "the cold node stranded on wedged assigned heads instead of stopping them and \
             descending to the healthy 1.0.0:\n{log}"
        ));
    }
    // Durability: the committed record names 1.0.0, so a restart never climbs back onto a wedged head.
    let settled = wait_for_installed_version(&dir, "1.0.0", CONVERGE_TIMEOUT);
    let wedge_stopped = !pid_alive(wedged_pid);
    drop(node);
    if !settled {
        return fail(
            "the descended-to 1.0.0 served but the committed install record never settled on it",
        );
    }
    if !wedge_stopped {
        return fail(format!(
            "the wedged head's workload (pid {wedged_pid}) was left running by the descent"
        ));
    }
    ok("a cold node stopped and descended past two assigned heads that applied cleanly but never became healthy");
    Ok(())
}

/// The signed reconciler owns readiness. Its `healthcheck` operation — the published readiness
/// gate — must run before a cold-installed release is put in rotation AND before an upgraded
/// candidate is committed, under the reserved `boot` identity for the former and the transaction's
/// own attempt id for the latter.
pub(crate) fn lifecycle_healthcheck_gates_readiness(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21181";
    let svc = "127.0.0.1:21182";
    let dir = ctx.work.join("lifecycle-verify");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let cmd = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .check_interval("1s")
        .health_grace("5s")
        .workload(svc)
        .command()?;
    let _node = Proc::spawn("lifecycle-verify", cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the lifecycle-gated deployment never came up at v1.0.0");
    }
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail("the lifecycle-gated deployment never upgraded to v2.0.0");
    }
    // The upgrade's readiness gate runs AFTER its workload is already serving 2.0.0: `converge` starts
    // the candidate, and only then does the transaction's `healthcheck` run under the attempt id.
    // So the version probe above returns strictly before the gate is recorded, and reading the
    // receipt once only ever passed by out-racing that window — which on a slower machine it loses.
    // Poll for both gates instead; the deadline is what makes "never gated" mean never.
    let mut gates: Vec<String> = Vec::new();
    let mut gated_install = false;
    let mut gated_upgrade = false;
    wait_until(EVENT_TIMEOUT, || {
        gates = fixture::operations(&fixture::root(&dir))
            .into_iter()
            .filter(|invocation| invocation.operation == Operation::Healthcheck)
            .map(|invocation| invocation.id)
            .collect();
        gated_install = gates.iter().any(|id| id == attempt::BOOT);
        gated_upgrade = gates.iter().any(|id| !attempt::is_reserved(id));
        gated_install && gated_upgrade
    });
    if !gated_install {
        return fail(format!(
            "the reconciler's healthcheck operation never gated the first install: {gates:?}"
        ));
    }
    if !gated_upgrade {
        return fail(format!(
            "the reconciler's healthcheck operation never gated the upgrade transaction: {gates:?}"
        ));
    }
    ok("the reconciler healthcheck gated both the first install and the upgrade");
    Ok(())
}

pub(crate) fn key_perms(ctx: &Ctx) -> R {
    use std::os::unix::fs::PermissionsExt;
    let dir = ctx.work.join("keyperms");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    // Every key `server init` mints, including the standby root that becomes the fleet-wide
    // root on the next rotate-root.
    for role in ["root", "root.next", "targets", "snapshot", "timestamp"] {
        let mode = std::fs::metadata(ctx.key(&dir, role))
            .map_err(str_err)?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return fail(format!("{role} key perms are {mode:o}, expected 600"));
        }
    }
    ok("TUF role keys are owner-only (0600)");
    Ok(())
}
