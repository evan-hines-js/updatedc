use super::super::*;
pub(crate) fn persisted_rejection(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21084", "127.0.0.1:21094");
    let dir = ctx.work.join("reject");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    // Broken v2: the `server` binary exits immediately on the app's args.
    ctx.publish(&dir, "app", "2.0.0", &ctx.server.clone())?;
    let _server = ctx.serve(&dir, srv)?;

    let make = || {
        Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
            .check_interval("1s")
            .health_grace("1s")
            .health(svc)
            .guardian()
    };

    // Run 1: apply the crashing v2. The guardian rolls the crash up, the init system
    // restarts the tower, and recovery rejects v2 and rolls back to v1 — persisting the
    // rejection so the failed bytes are never re-applied.
    {
        let cmd = make()?;
        let sup = Service::spawn("reject-1", &cmd);
        if !sup.wait_for_log("update 2.0.0 crashed before commit; rejecting it", 30) {
            return fail("the crashing v2 was not rejected on recovery");
        }
        if !wait_for_version(svc, "1.0.0", 20) {
            return fail("the tower did not recover to v1.0.0 after rejecting v2");
        }
        let persisted = wait_until(10, || {
            std::fs::metadata(with_suffix(&app, ".installed.rejected"))
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        });
        if !persisted {
            return fail("rejection was not persisted to disk");
        }
    }
    // Reap any orphaned app before the second tower reuses the port (macOS only).
    kill_stray(&app);

    // Run 2 (a fresh tower): must NOT reapply the known-bad v2.
    {
        let cmd = make()?;
        let sup = Service::spawn("reject-2", &cmd);
        if !wait_for_version(svc, "1.0.0", 20) {
            return fail("v1.0.0 did not come back up on restart");
        }
        std::thread::sleep(Duration::from_secs(4));
        if sup.log_contains("applying update 1.0.0 -> 2.0.0") {
            return fail("restart re-applied the known-bad v2");
        }
    }
    kill_stray(&app);
    ok("a crashing release was rejected on recovery and NOT reapplied after a restart");
    Ok(())
}

// ===========================================================================
// 6. A supervisor crash re-adopts the running app instead of restarting it.
// ===========================================================================
