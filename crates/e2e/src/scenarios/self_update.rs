use super::super::*;

/// The tower for the self-update scenarios: the guardian runs supervisor v1, which
/// self-updates from the `supervisor` TUF product; the app is health-gated.
fn tower(ctx: &Ctx, dir: &Path, srv: &str, svc: &str, app: &Path, sup_v1: &Path) -> R<Command> {
    Sup::new(ctx, dir, srv, "app", appcmd(app, &["--addr", svc]))
        .health(svc)
        .check_interval("60s")
        .health_grace("3s")
        .supervisor_check_interval("1s")
        .ready_timeout("15")
        .supervisor_bin(sup_v1)
        .guardian()
}

/// Read the guardian's frozen pointer format rather than treating its header and path
/// as one filesystem path. This deliberately mirrors the public on-disk contract the
/// E2E test is meant to verify, without reaching into bootstrap's private module.
fn desired_supervisor(dir: &Path) -> R<PathBuf> {
    let pointer = dir.join("guardian-state/desired-supervisor");
    let text = std::fs::read_to_string(&pointer).map_err(str_err)?;
    let mut lines = text.lines();
    if lines.next() != Some("supervisor-v1") {
        return fail(format!("invalid desired-supervisor header in {pointer:?}"));
    }
    let path = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| format!("missing path in desired-supervisor: {text:?}"))?;
    if lines.next().is_some() {
        return fail(format!("trailing data in desired-supervisor: {text:?}"));
    }
    Ok(PathBuf::from(path))
}

/// The guardian commits a self-updated supervisor (v1 → v2) by pointer flip, and the
/// application is never disturbed — the guardian owns it across the whole handoff.
pub(crate) fn supervisor_self_update(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21086", "127.0.0.1:21096");
    let dir = ctx.work.join("selfupd");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    let sup_v1 = supervisor_v(ctx, "1.0.0");

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // The supervisor is its own TUF product; 1.0.0 is the running build.
    ctx.publish(&dir, "supervisor", "1.0.0", &sup_v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let boot = Proc::spawn("guardian", &mut tower(ctx, &dir, srv, svc, &app, &sup_v1)?)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        kill_stray(&app);
        return fail("app never came up under the tower");
    }
    if !boot.wait_for_log("started application pid", 10) {
        return fail("supervisor did not record the application launch");
    }
    let pid1 = pid_number_after(&boot.captured_log(), "started application pid")
        .ok_or("could not read the guardian-reported application PID")?;
    ok("tower up on supervisor 1.0.0; app live");

    // Publish supervisor 2.0.0 (different bytes). The running supervisor stages it,
    // hands its path to the guardian, and exits; the guardian activates it under a
    // readiness gate, the new supervisor adopts the running app and proves ready, and
    // the guardian commits the desired-supervisor pointer.
    ctx.publish(&dir, "supervisor", "2.0.0", &supervisor_v(ctx, "2.0.0"))?;
    let committed = boot.wait_for_log("committed as the supervisor", 45);
    // The new supervisor adopts the app the guardian already owns — no restart.
    let adopted =
        committed && wait_until(15, || boot.log_contains("adopted the running application"));

    let pid2 = pid_after(&boot.captured_log(), "adopted the running application");
    let undisturbed = adopted && pid2 == Some(pid1) && pid_alive(pid1);
    let desired = desired_supervisor(&dir)?;
    kill_stray(&app);

    if !committed {
        return fail("guardian did not commit the self-updated supervisor 2.0.0");
    }
    if !adopted {
        return fail("the committed supervisor never adopted the running application");
    }
    if !undisturbed {
        return fail(format!(
            "the self-update disrupted the application (pid {pid1} -> {pid2:?})"
        ));
    }
    // The committed pointer must name the exact published v2 bytes. Comparing content
    // makes this separator-independent and proves more than a path substring does.
    let expected_v2_sha = sha256_hex(&supervisor_v(ctx, "2.0.0"));
    if !desired.is_file() || sha256_hex(&desired) != expected_v2_sha {
        return fail(format!(
            "desired-supervisor did not advance to the staged v2 binary: {desired:?}"
        ));
    }
    ok(&format!(
        "supervisor self-updated 1.0.0 -> 2.0.0 by pointer flip; the app kept running (pid {pid1})"
    ));
    Ok(())
}

/// A supervisor candidate that cannot execute at all is rolled back by the guardian
/// (the desired pointer stays put), rejected by the supervisor, and never retried. The
/// application is untouched throughout — the failure in-process recovery could not survive.
pub(crate) fn supervisor_self_update_rollback(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21087", "127.0.0.1:21097");
    let dir = ctx.work.join("selfupd-rollback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    let sup_v1 = supervisor_v(ctx, "1.0.0");

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "supervisor", "1.0.0", &sup_v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let boot = Proc::spawn("guardian", &mut tower(ctx, &dir, srv, svc, &app, &sup_v1)?)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        kill_stray(&app);
        return fail("app never came up under the tower");
    }
    if !boot.wait_for_log("started application pid", 10) {
        return fail("supervisor did not record the application launch");
    }
    let pid1 = pid_number_after(&boot.captured_log(), "started application pid")
        .ok_or("could not read the guardian-reported application PID")?;
    ok("tower up on supervisor 1.0.0; app live");

    // Publish a supervisor "2.0.0" whose bytes cannot execute. The running supervisor
    // stages and hash-verifies it (TUF only attests the bytes) and hands it off; the
    // guardian cannot launch the candidate, rolls the pointer back, and marks it; the
    // supervisor rejects the hash and never re-stages it.
    let broken = dir.join("broken-supervisor");
    std::fs::write(&broken, b"NOT-A-RUNNABLE-SUPERVISOR-BINARY\n").map_err(str_err)?;
    ctx.publish(&dir, "supervisor", "2.0.0", &broken)?;

    let rejected = boot.wait_for_log("rejecting", 40);
    // No loop: once the candidate is rejected, the supervisor must stop re-staging it.
    std::thread::sleep(Duration::from_secs(6));
    let recorded = boot.wait_for_log("recorded rejected supervisor candidate", 5);
    let served = wait_for_version(svc, "1.0.0", 5);
    let pid2 = pid_after(&boot.captured_log(), "adopted the running application");
    let desired = desired_supervisor(&dir)?;
    kill_stray(&app);

    if !rejected {
        return fail("guardian did not roll back the unlaunchable supervisor candidate");
    }
    if !served || pid2 != Some(pid1) || !pid_alive(pid1) {
        return fail(format!(
            "the failed self-update disrupted the application (pid {pid1} -> {pid2:?})"
        ));
    }
    if !recorded {
        return fail("the failed candidate was not recorded as rejected by the supervisor");
    }
    // The pointer must still resolve to the exact v1 bytes, irrespective of Windows
    // versus Unix path separators. A substring test could silently pass on Windows.
    if !desired.is_file() || sha256_hex(&desired) != sha256_hex(&sup_v1) {
        return fail(format!(
            "desired-supervisor did not remain on the committed v1 binary: {desired:?}"
        ));
    }
    ok("unlaunchable supervisor candidate rolled back, rejected, and never retried; app untouched");
    Ok(())
}
