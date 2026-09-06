use super::super::*;
use updated_contracts::reconciler::{attempt, Operation};

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
