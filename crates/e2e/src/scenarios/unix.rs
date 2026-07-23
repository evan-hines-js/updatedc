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

/// The lifecycle provider owns verification. It records `verify`/`periodic` observations and
/// passes only while the managed child is alive.
pub(crate) fn lifecycle_verify_gates_readiness(ctx: &Ctx) -> R {
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
    let probe_log = dir.join("health-probe.log");
    let lifecycle = vec![
        "sh".into(),
        "-c".into(),
        format!(
            "op=$1; shift; pid=; while [ \"$#\" -gt 0 ]; do case \"$1\" in --managed-pid) pid=$2; shift 2;; --) break;; *) shift 2;; esac; done; case \"$op\" in verify|periodic) echo probe >> {log}; test -n \"$pid\"; exec kill -0 \"$pid\";; *) exit 0;; esac",
            log = probe_log.display()
        ),
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
        return fail("lifecycle-verified deployment never came up at v1.0.0");
    }
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail("lifecycle-verified deployment never upgraded to v2.0.0");
    }
    if !std::fs::read_to_string(&probe_log)
        .unwrap_or_default()
        .lines()
        .any(|line| line == "probe")
    {
        return fail("the lifecycle verify hook was never invoked as the readiness gate");
    }
    kill_stray(&app);
    ok("lifecycle verify gated first install and upgrade");
    Ok(())
}

pub(crate) fn key_perms(ctx: &Ctx) -> R {
    use std::os::unix::fs::PermissionsExt;
    let dir = ctx.work.join("keyperms");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    for role in ["root", "targets", "snapshot", "timestamp"] {
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

// ===========================================================================
// 10. Crash at every update boundary; a fresh supervisor recovers each time.
// ===========================================================================
