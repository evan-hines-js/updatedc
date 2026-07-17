use super::super::*;

/// Crash the supervisor at every application-update transaction boundary; the guardian
/// relaunches it and recovery (driven by the on-disk journal) drives the update to a
/// committed version. The chaos is one-shot, so the relaunched supervisor recovers
/// rather than crashing again. Each boundary runs in a fully isolated dir + repo so
/// there is no shared state to reset.
pub(crate) fn chaos_recovery(ctx: &Ctx) -> R {
    // Enumerated from the supervisor binary, not hand-copied — so the scenario tests
    // exactly the crossings the supervisor defines (see `Ctx::chaos_boundaries`).
    let boundaries = ctx.chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 21200 + index);
        let svc = format!("127.0.0.1:{}", 21300 + index);
        let dir = ctx.work.join(format!("chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
        let app = dir.join(format!("app{}", ctx.exe));
        std::fs::copy(&v1, &app).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        ctx.publish(&dir, "app", "2.0.0", &v2)?;
        let server = ctx.serve(&dir, &srv)?;

        let mut cmd = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
            .health(&svc)
            .check_interval("1s")
            .health_grace("2s")
            .guardian()?;
        cmd.env("UPDATED_CHAOS_POINT", point);
        let boot = Proc::spawn("chaos", &mut cmd)?;

        // The supervisor applies the update, crashes once at `point`; the guardian
        // must observe that crash and launch a fresh supervisor. Merely seeing v2 at
        // the health endpoint is insufficient for the later boundaries: the new app
        // can become healthy just before the old supervisor dies.
        let crash_seen = boot.wait_for_log(&format!("CHAOS: exiting at boundary \"{point}\""), 30);
        let relaunched = wait_until(30, || boot.log_count("launched supervisor") >= 2);

        // Prove durable convergence as well as liveness: installed state names the
        // exact v2 bytes and the transaction journal is gone. This catches recovery
        // that briefly serves v2 but leaves a half-committed transaction on disk.
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/transaction.json");
        let durable = wait_until(40, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "2.0.0"
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "2.0.0", 10);
        let log = boot.captured_log();
        drop(boot);
        drop(server);
        kill_stray(&dir.join("install"));
        let stopped = wait_until(10, || http_text(&format!("http://{svc}/version")).is_none());
        if !crash_seen || !relaunched || !durable || !live || !stopped {
            return fail(format!(
                "recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 relaunched={relaunched}, durable={durable}, live={live}, stopped={stopped}); log:\n{log}"
            ));
        }
    }
    ok("every update crash boundary recovered to the committed version");
    Ok(())
}
