use super::super::*;
pub(crate) fn app_update_and_rollback(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21080", "127.0.0.1:21090");
    let dir = ctx.work.join("app");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("2s")
        .health_grace("2s")
        // This scenario exercises two consecutive update edges. Keep the real
        // confirmation gate, but shorten its window so v3 is not published until the
        // v1 -> v2 edge has been confirmed.
        .confirmation_window("3s")
        .health(svc)
        .guardian()?;
    // Under a simulated init system: a crashing update is rolled back by recovery on the
    // next boot (the guardian rolls the crash up and exits), not by an in-process rollback.
    let sup = Service::spawn("tower", &cmd);

    if !wait_for_version(svc, "1.0.0", 25) {
        return fail("service never came up at v1.0.0");
    }
    ok("v1.0.0 live from the TUF repository");

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", 30) {
        return fail("service did not upgrade to v2.0.0");
    }
    ok("unattended upgrade to v2.0.0");

    if !sup.wait_for_log("update 2.0.0 confirmed; confirmation window passed", 15) {
        return fail("v2.0.0 was not confirmed before the next update");
    }

    // A validly signed target that exits immediately (the `server` binary rejects the
    // app's args): a real swap whose application crashes before commit. The guardian rolls
    // it up; the restarted supervisor rejects the crashing release and recovers to v2.
    ctx.publish(&dir, "app", "3.0.0", &ctx.server.clone())?;
    if !sup.wait_for_log(
        "restoring predecessor 2.0.0 after interrupted activation of 3.0.0",
        40,
    ) {
        return fail("supervisor did not reject the crashing v3.0.0 on recovery");
    }
    if !wait_for_version(svc, "2.0.0", 15) {
        return fail("service did not recover to v2.0.0 after the crashing v3.0.0");
    }
    ok("broken v3.0.0 applied, crashed before commit, was rejected, and the tower recovered to v2.0.0");
    kill_stray(&app);
    Ok(())
}

// ===========================================================================
// A committed update that PASSES its health check and then crashes within its
// confirmation window is reverted to the previous version and the bad release
// rejected — one strike, the failure a finite health window cannot catch.
// ===========================================================================
pub(crate) fn app_post_health_crash_reverts(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21089", "127.0.0.1:21099");
    let dir = ctx.work.join("crashloop");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    // The child args serve both versions; only v2's baked-in version matches
    // `--crash-version`, so v2 exits ~4s after launch — after the 2s health grace,
    // i.e. a post-commit crash the health gate cannot see. v1 ignores the flag.
    let cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(
            &app,
            &[
                "--addr",
                svc,
                "--crash-version",
                "2.0.0",
                "--crash-after-ms",
                "4000",
            ],
        ),
    )
    .check_interval("2s")
    .health_grace("2s")
    .health(svc)
    .guardian()?;
    // The init system restarts the tower when the app crashes; on that boot the supervisor
    // sees the unconfirmed update crashed and reverts it (one strike).
    let sup = Service::spawn("tower", &cmd);

    if !wait_for_version(svc, "1.0.0", 25) {
        kill_stray(&app);
        return fail("service never came up at v1.0.0");
    }
    ok("v1.0.0 live");

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    // v2 commits (passes health), then crashes within its window; the supervisor reverts.
    if !sup.wait_for_log("reverting to 1.0.0", 60) {
        kill_stray(&app);
        return fail("supervisor did not revert the crashing v2.0.0");
    }
    if !wait_for_version(svc, "1.0.0", 20) {
        kill_stray(&app);
        return fail("service did not recover to v1.0.0 after the revert");
    }
    let rejected = std::fs::read_to_string(dir.join("install/state/rejected")).unwrap_or_default();
    kill_stray(&app);
    if rejected.trim().is_empty() {
        return fail("the crashing release's hash was not rejected");
    }
    ok("a post-health crash reverted to v1.0.0 and rejected the bad release (one strike)");
    Ok(())
}

pub(crate) fn group_peer_failure_is_node_local(ctx: &Ctx) -> R {
    let root = ctx.work.join("group-peer-isolation");
    let v1 = app_v(ctx, "1.0.0");
    let v2 = app_v(ctx, "2.0.0");
    let nodes = [
        ("healthy", "127.0.0.1:21120", "127.0.0.1:21130", false),
        ("failing", "127.0.0.1:21121", "127.0.0.1:21131", true),
    ];
    let mut services = Vec::new();
    let mut servers = Vec::new();

    for (name, repository_addr, service_addr, fails) in nodes {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let app = dir.join(format!("app{}", ctx.exe));
        std::fs::copy(&v1, &app).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        servers.push(ctx.serve(&dir, repository_addr)?);

        let mut args = vec!["--addr", service_addr];
        if fails {
            args.extend(["--crash-version", "2.0.0", "--crash-after-ms", "4000"]);
        }
        let command = Sup::new(ctx, &dir, repository_addr, "app", appcmd(&app, &args))
            .check_interval("1s")
            .health_grace("2s")
            .confirmation_window("8s")
            .health(service_addr)
            .guardian()?;
        services.push((name, dir, app, service_addr, Service::spawn(name, &command)));
    }

    for (_, _, _, address, _) in &services {
        if !wait_for_version(address, "1.0.0", 25) {
            return fail(format!("node at {address} did not start at 1.0.0"));
        }
    }
    for (_, dir, _, _, _) in &services {
        ctx.publish(dir, "app", "2.0.0", &v2)?;
    }
    if !wait_for_version("127.0.0.1:21130", "2.0.0", 30) {
        return fail("healthy peer did not commit 2.0.0");
    }
    if !services[1].4.wait_for_log("reverting to 1.0.0", 60)
        || !wait_for_version("127.0.0.1:21131", "1.0.0", 20)
    {
        return fail("failing peer did not roll back to 1.0.0");
    }
    if !services[0]
        .4
        .wait_for_log("update 2.0.0 confirmed; confirmation window passed", 20)
        || !wait_for_version("127.0.0.1:21130", "2.0.0", 5)
    {
        return fail("healthy peer was incorrectly rolled back with its failing peer");
    }
    for (_, _, app, _, _) in &services {
        kill_stray(app);
    }
    drop(servers);
    ok("one node rolled back locally while its group peer remained committed at 2.0.0");
    Ok(())
}

// ===========================================================================
// 2. A tampered pinned root is rejected at load (fail closed).
// ===========================================================================
