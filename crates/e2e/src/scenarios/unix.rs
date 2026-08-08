use super::super::*;

/// The *wedge* twin of `cold_install_descends_past_broken_head`. There the broken heads crash
/// (dead process); here they stay **alive but never become healthy** — an entrypoint that binds
/// nothing and sleeps forever, so the boot health gate fails while the process keeps running.
/// That is the case that regressed in the fleet: the guardian keeps the wedged head alive across
/// the supervisor restart, and a naive descend would *adopt* that stale process and health-gate it,
/// then reject the healthy release it just installed. Proof of the fix: the node must stop each
/// wedged head, descend past both, and actually serve the healthy floor (1.0.0).
pub(crate) fn cold_install_descends_past_wedged_head(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21330", "127.0.0.1:21331");
    let probes = "127.0.0.1:21332";
    let dir = ctx.work.join("cold-install-wedge");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    // The healthy release below the wedged heads.
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Two "wedged" heads: an executable that stays alive but never binds the readiness port, so it
    // passes exec (no crash) yet fails the boot health gate forever. `exec sleep` ignores the
    // supervisor's appended argv. The assigned head is the newest (3.0.0), so recovery must stop
    // and descend past both 3.0.0 and 2.0.0 to reach the healthy 1.0.0.
    let wedged = dir.join("wedged-app");
    std::fs::write(&wedged, b"#!/bin/sh\nexec sleep 100000\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &wedged)?;
    ctx.publish(&dir, "app", "3.0.0", &wedged)?;
    let _server = ctx.serve(&dir, srv)?;
    let unplaced = dir.join(format!("not-preinstalled{}", ctx.exe));
    let command = Sup::new(ctx, &dir, srv, "app", appcmd(&unplaced, &["--addr", svc]))
        .cold_install()
        .ordered_install_fallback()
        .readiness_health(svc)
        .check_interval("1s")
        // A short grace keeps the per-head wedge detection quick; the head never becomes healthy,
        // so the gate fails after the grace and the boot rejects it and descends.
        .health_grace("3s")
        .guardian_probes(probes)
        .guardian()?;
    let tower = Service::spawn("cold-install-wedge", &command);
    // Recovery is proven only when the healthy 1.0.0 actually serves — i.e. the descent launched
    // the freshly-installed bytes rather than adopting a stale wedged process and rejecting 1.0.0.
    const DESCENT_TIMEOUT: u64 = 120;
    if !wait_for_version(svc, "1.0.0", DESCENT_TIMEOUT) {
        let log = tower.captured_log();
        return fail(format!(
            "cold node stranded on wedged assigned heads instead of stopping them and descending to \
             the healthy 1.0.0 (a stale-process adopt would reject 1.0.0's bytes here):\n{log}"
        ));
    }
    // Durability: the committed record names 1.0.0, so a restart never climbs back onto a wedged head.
    let state_path = dir.join("install/state/installed.json");
    let settled = wait_until(DESCENT_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&state_path),
            updated::state::Installed::Present(ref state) if state.release.version == "1.0.0"
        )
    });
    drop(tower);
    kill_stray(&dir.join("install"));
    if !settled {
        return fail(
            "descended app served 1.0.0 but the committed install record never settled on it",
        );
    }
    ok("cold-installed wedged assigned heads, stopped them, and ordered fallback descended past two to the healthy 1.0.0");
    Ok(())
}

/// The signed reconciler owns readiness. Its `healthcheck` operation — the published readiness
/// gate — must run before a cold-installed release is put in rotation AND before an upgraded
/// candidate is committed, under the reserved `boot` identity for the former and the transaction's
/// own attempt id for the latter.
pub(crate) fn lifecycle_healthcheck_gates_readiness(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21181";
    let svc = "127.0.0.1:21182";
    let probes = "127.0.0.1:21183";
    let dir = ctx.work.join("lifecycle-verify");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    // The one shared reconciler fixture, which speaks the published operation vocabulary and
    // records every invocation. A scenario-local reconciler would be free to answer a spelling
    // the supervisor never invokes and quietly assert nothing.
    let fixture = dir.join("lifecycle-fixture");
    let lifecycle = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "accept-managed".into(),
    ];
    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .cold_install()
        .check_interval("1s")
        .health_grace("5s")
        .guardian_probes(probes)
        .lifecycle(lifecycle)
        .guardian()?;
    let _sup = Proc::spawn("supervisor", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("lifecycle-gated deployment never came up at v1.0.0");
    }
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail("lifecycle-gated deployment never upgraded to v2.0.0");
    }
    let observations = std::fs::read_to_string(fixture.join("operations.log")).unwrap_or_default();
    let gates: Vec<&str> = observations
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter_map(|(operation, id)| (operation == "healthcheck").then_some(id))
        .collect();
    if !gates.contains(&"boot") {
        return fail(format!(
            "the reconciler's healthcheck operation never gated the first install:\n{observations}"
        ));
    }
    if !gates.iter().any(|id| *id != "boot" && *id != "periodic") {
        return fail(format!(
            "the reconciler's healthcheck operation never gated the upgrade transaction:\n{observations}"
        ));
    }
    kill_stray(&app);
    ok("the reconciler healthcheck gated both the first install and the upgrade");
    Ok(())
}

pub(crate) fn key_perms(ctx: &Ctx) -> R {
    use std::os::unix::fs::PermissionsExt;
    let dir = ctx.work.join("keyperms");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
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
