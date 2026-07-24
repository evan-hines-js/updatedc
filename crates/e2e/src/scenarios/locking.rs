use super::super::*;
pub(crate) fn single_instance_lock(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21082", "127.0.0.1:21092");
    let dir = ctx.work.join("lock");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut first_cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("60s")
        .health_grace("2s")
        .readiness_health(svc)
        .guardian()?;
    let first = Proc::spawn("supervisor-1", &mut first_cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("first supervisor never came up");
    }
    if !first.wait_for_log("started managed application pid", EVENT_TIMEOUT) {
        return fail("first supervisor did not record the application launch");
    }
    let first_pid = pid_number_after(&first.captured_log(), "started managed application pid")
        .ok_or("could not read the guardian-reported application PID")?;

    // The second instance uses the SAME launch spec as the first. Building a Sup command republishes
    // the node's signed assignment (harness setup), so a *different* spec here would republish an
    // assignment whose runtime args changed — which the live first supervisor correctly picks up and
    // relaunches on, disturbing the owner via legitimate reassignment rather than the lock we are
    // testing. Identical args make that republish a no-op, isolating the instance lock. The lock
    // rejection is still asserted directly below (the second never binds a port — it is refused
    // before launching the application — so reusing the first's address is safe).
    let second_cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("60s")
        .health_grace("1s")
        .guardian()?;
    let second = Service::spawn("supervisor-2", &second_cmd);
    if !second.wait_for_log("already owns this install", EVENT_TIMEOUT) {
        return fail("second supervisor was not refused with the expected lock message");
    }
    let second_log = second.captured_log();
    let first_still_live = wait_for_version(svc, "1.0.0", EVENT_TIMEOUT);
    let pid_unchanged = pid_alive(first_pid);
    if second_log.contains("started managed application pid") || !first_still_live || !pid_unchanged
    {
        return fail(format!(
            "lock rejection disturbed the owner (live={first_still_live}, \
             pid_unchanged={pid_unchanged}):\n{second_log}"
        ));
    }
    drop(second);
    kill_stray(&app);
    ok("a second supervisor on the same install was refused by the instance lock");
    Ok(())
}

// ===========================================================================
// 5. A health-check-failed release stays rejected across a restart.
// ===========================================================================
