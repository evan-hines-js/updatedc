use super::super::*;

// ===========================================================================
// updated-oneshot: update-on-launch for a non-daemon program. It checks the TUF
// repository once, atomically swaps in a newer verified binary, then execs the
// program (which here is the long-running sampleapp, so we can observe it over
// HTTP). This is the same [application]/[repository] config the supervisor reads.
// ===========================================================================
pub(crate) fn oneshot_updates_on_launch(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21077", "127.0.0.1:21095");
    let dir = ctx.work.join("oneshot-update");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    // The installer's baseline: the v1.0.0 binary on disk.
    std::fs::copy(&v1, &app).map_err(str_err)?;

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let _server = ctx.serve(&dir, srv)?;

    // One invocation: it must update 1.0.0 -> 2.0.0 and then exec the app, which
    // comes up serving 2.0.0. No supervisor, no bootstrap — just the updater.
    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc])).oneshot()?;
    let one = Proc::spawn("oneshot", &mut cmd)?;

    if !wait_for_version(svc, "2.0.0", 30) {
        kill_stray(&app);
        return fail("updated-oneshot did not update to v2.0.0 and launch it");
    }
    if !one.wait_for_log("updated 1.0.0 -> 2.0.0", 5) {
        kill_stray(&app);
        return fail("updated-oneshot did not report applying the update");
    }
    // The committed record must name the version it launched, so the NEXT launch
    // starts from 2.0.0 rather than re-updating.
    let state =
        std::fs::read_to_string(dir.join("install/state/installed.json")).unwrap_or_default();
    kill_stray(&app);
    if !state.contains("\"version\":\"2.0.0\"") {
        return fail(format!(
            "installed-state was not recorded as 2.0.0: {state:?}"
        ));
    }
    ok("updated-oneshot updated 1.0.0 -> 2.0.0 on launch and exec'd the new binary");
    Ok(())
}

// ===========================================================================
// Update availability must never gate the launch: with the repository
// unreachable, the updater logs that it is skipping the update and still execs
// the current (baseline) binary. This is the non-daemon analog of the
// supervisor's "repository availability never gates the application".
// ===========================================================================
pub(crate) fn oneshot_launches_without_repository(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21078", "127.0.0.1:21076");
    let dir = ctx.work.join("oneshot-offline");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;

    // A pinned root exists (init) so trust can be established, but nothing serves the
    // metadata — the refresh fails, exactly like a machine that booted before its
    // network came up.
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    // Deliberately do NOT serve the repository.

    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc])).oneshot()?;
    let one = Proc::spawn("oneshot", &mut cmd)?;

    if !wait_for_version(svc, "1.0.0", 30) {
        kill_stray(&app);
        return fail("updated-oneshot did not launch the current version when the repo was down");
    }
    let skipped = one.wait_for_log("update skipped", 5);
    kill_stray(&app);
    if !skipped {
        return fail("updated-oneshot did not report skipping the update with no repository");
    }
    ok("updated-oneshot launched the baseline v1.0.0 despite an unreachable repository");
    Ok(())
}
