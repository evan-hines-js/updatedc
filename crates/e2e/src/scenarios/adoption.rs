use super::super::*;
/// A supervisor crash does not disturb the application: the guardian owns the app, so it
/// simply relaunches the (disposable) supervisor, which adopts the still-running app
/// without restarting it. This is the whole point of the guardian/supervisor split.
pub(crate) fn supervisor_crash_preserves_app(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21081", "127.0.0.1:21091");
    let dir = ctx.work.join("supervisor-adoption");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut boot = Proc::spawn(
        "guardian",
        &mut Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
            .check_interval("60s")
            // The default health policy requires multiple polls; be generous on CI.
            .health_grace("5s")
            .health(svc)
            .guardian()?,
    )?;
    if !wait_for_version(svc, "1.0.0", 60) {
        return fail("app never came up under the tower");
    }
    // Wait until the supervisor has launched the app (so the guardian's "launched
    // supervisor" line with the PID is present), then read that supervisor PID.
    if !boot.wait_for_log("started application pid", 15) {
        return fail("the supervisor never reported launching the application");
    }
    let initial_log = boot.captured_log();
    let sup_pid = pid_after(&initial_log, "launched supervisor")
        .ok_or("could not find the supervisor PID in the guardian log")?;
    let pid1 = pid_number_after(&initial_log, "started application pid")
        .ok_or("supervisor did not record the guardian-reported application PID")?;

    // Crash ONLY the supervisor (not the guardian, not the app). The guardian owns the
    // app, so it keeps running; the guardian relaunches a fresh supervisor.
    kill_pid(sup_pid);
    if !wait_for_version(svc, "1.0.0", 15) {
        return fail("the application did not survive the supervisor crash");
    }

    // The guardian relaunches the supervisor (a second "launched supervisor"), and the
    // new supervisor adopts the still-running app rather than launching a duplicate.
    let relaunched = wait_until(30, || boot.log_count("launched supervisor") >= 2);
    let adopted =
        relaunched && wait_until(15, || boot.log_contains("adopted the running application"));
    if !adopted {
        return fail(format!(
            "the guardian did not relaunch the supervisor to re-adopt the app; exited={}, log:\n{}",
            boot.has_exited(),
            boot.captured_log()
        ));
    }
    if !wait_for_version(svc, "1.0.0", 30) {
        return fail("app not serving after the supervisor relaunch");
    }
    let pid2 = pid_after(&boot.captured_log(), "adopted the running application")
        .ok_or("new supervisor did not record the guardian-owned application PID")?;
    if pid1 != pid2 {
        return fail(format!(
            "the supervisor crash restarted the app (pid {pid1} -> {pid2}) instead of leaving it"
        ));
    }
    kill_stray(&app);
    ok(&format!(
        "supervisor crash recovered by the guardian relaunching it; app kept running (pid {pid1})"
    ));
    Ok(())
}

/// A clean stop is transparent to the init system: a `SIGTERM` to the guardian (the
/// service's main process) — not to the app, not to the whole group — must be forwarded
/// *down* so the entire tower (guardian, supervisor, application) exits on its own, with no
/// external reaper. This is the guarantee that lets the guardian run under systemd/launchd
/// with nothing left orphaned — and, on macOS (no `PR_SET_PDEATHSIG`), the only path that
/// reaps the app without a `pkill`.
pub(crate) fn clean_stop_reaps_the_whole_tower(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21072", "127.0.0.1:21073");
    let dir = ctx.work.join("clean-stop");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut boot = Proc::spawn(
        "tower",
        &mut Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
            .check_interval("60s")
            .health_grace("5s")
            .health(svc)
            .guardian()?,
    )?;

    if !wait_for_version(svc, "1.0.0", 60) {
        return fail("app never came up under the tower");
    }
    if !boot.wait_for_log("started application pid", 15) {
        return fail("the supervisor never reported launching the application");
    }
    let app_pid = pid_number_after(&boot.captured_log(), "started application pid")
        .ok_or("supervisor did not record the guardian-reported application PID")?;
    let guardian_pid = boot.pid();
    let sup_pid = pid_after(&boot.captured_log(), "launched supervisor");
    if !pid_alive(app_pid) {
        return fail("the application was not running before the stop");
    }

    // The init system's clean stop: SIGTERM the guardian ONLY. The supervisor and the app
    // run in their own process groups and never see this signal directly — the guardian
    // must roll it down to them.
    term_pid(guardian_pid);

    // The guardian reaps the supervisor and the app, then exits — all WITHOUT any external
    // reaper. Assert the whole tree is gone before dropping `boot` (whose own teardown would
    // otherwise mask a leak).
    let app_gone = wait_until(15, || !pid_alive(app_pid));
    let sup_gone = sup_pid.is_none_or(|s| wait_until(5, || !pid_alive(s)));
    let guardian_exited = wait_until(5, || boot.has_exited());

    if !app_gone || !sup_gone || !guardian_exited {
        // Reap any leak so a failure here does not poison later scenarios.
        kill_stray(&app);
        if let Some(s) = sup_pid {
            kill_pid(s);
        }
        return fail(format!(
            "a clean stop leaked processes (app_gone={app_gone}, sup_gone={sup_gone}, \
             guardian_exited={guardian_exited}) — the guardian did not forward the stop down"
        ));
    }
    // Deliberately no kill_stray on success: the whole point is that nothing external was
    // needed to reap the tower.
    ok("a clean SIGTERM to the guardian reaped the whole tower — app, supervisor, guardian — with no external reaper");
    Ok(())
}
