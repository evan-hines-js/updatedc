use super::super::*;
pub(crate) fn tampered_root_fails_closed(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21088";
    let dir = ctx.work.join("badroot");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;

    let _server = ctx.serve(&dir, srv)?;
    // Building the command materializes and publishes the exact signed runtime before
    // corrupting the client copy; repository authoring correctly refuses a corrupt root.
    let cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(&app, &["--addr", "127.0.0.1:0"]),
    )
    .check_interval("1s")
    .health_grace("1s")
    .guardian()?;
    let enrollment_path = dir.join("guardian-state/enrollment.json");
    let mut enrollment: updated::enrollment::EnrollmentBundle =
        serde_json::from_slice(&std::fs::read(&enrollment_path).map_err(str_err)?)
            .map_err(|error| error.to_string())?;
    enrollment.routing_root.push_str("tampered");
    std::fs::write(
        &enrollment_path,
        serde_json::to_vec(&enrollment).map_err(|error| error.to_string())?,
    )
    .map_err(str_err)?;
    let tower = Service::spawn("bad-root", &cmd);
    if !wait_until(EVENT_TIMEOUT, || {
        tower
            .captured_log()
            .contains("resolving signed managed configuration")
    }) {
        return fail(format!(
            "tampered enrollment root did not produce a fail-closed result:\n{}",
            tower.captured_log()
        ));
    }
    let log = tower.captured_log();
    if log.contains("started managed application pid") || log.contains("upgraded to") {
        return fail(format!(
            "tampered enrollment trust authorized an application launch:\n{log}"
        ));
    }
    drop(tower);
    kill_stray(&app);
    ok("tampered enrollment trust was rejected before any application launch");
    Ok(())
}

pub(crate) fn signed_local_repair_without_network(ctx: &Ctx) -> R {
    let dir = ctx.work.join("signed-local-repair");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let v2 = app_v(ctx, "2.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;

    let sup = Sup::new(
        ctx,
        &dir,
        "127.0.0.1:1",
        "app",
        appcmd(&v1, &["--addr", "127.0.0.1:21140"]),
    )
    .local_repository()
    .check_interval("1s")
    .readiness_health("127.0.0.1:21140")
    .health_grace("2s");
    let cmd = sup.clone().guardian()?;
    let tower = Service::spawn("local-repair", &cmd);
    if !wait_for_version("127.0.0.1:21140", "1.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "local baseline did not start:\n{}",
            tower.captured_log()
        ));
    }

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    republish_assignment(&sup, "offline-repair")?;
    let active: updated::bundle::ReleaseId = serde_json::from_slice(
        &std::fs::read(sup.install_root.join("active-release")).map_err(str_err)?,
    )
    .map_err(|error| error.to_string())?;
    let active_dir = std::fs::read_dir(sup.install_root.join("versions"))
        .map_err(str_err)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{}-", active.version)))
        })
        .ok_or("active release directory was not found")?;
    let entrypoint = active_dir.join(format!("bin/app{}", ctx.exe));
    drop(tower);
    make_owner_writable(&entrypoint)?;
    std::fs::write(&entrypoint, b"locally modified and no longer trusted").map_err(str_err)?;

    let repaired_tower = Service::spawn("local-repair-restart", &cmd);
    if !wait_for_version("127.0.0.1:21140", "2.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "signed local repair did not replace the modified release without a server:\n{}",
            repaired_tower.captured_log()
        ));
    }
    let log = repaired_tower.captured_log();
    if !log.contains("repaired the committed application from signed local deployment 2.0.0") {
        return fail(format!("local repair path was not observed:\n{log}"));
    }
    drop(repaired_tower);
    ok("the modified release was stopped and replaced from a fully verified local signed deployment without network access");
    Ok(())
}
