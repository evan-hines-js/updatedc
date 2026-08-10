use super::super::*;
pub(crate) fn tampered_root_fails_closed(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21088", "127.0.0.1:21098");
    let dir = ctx.work.join("badroot");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;

    let _server = ctx.serve(&dir, srv)?;
    // Building the command materializes and publishes the exact signed runtime before
    // corrupting the client copy; repository authoring correctly refuses a corrupt root.
    let cmd = Node::new(ctx, &dir, srv, "app")
        .workload(svc)
        .check_interval("1s")
        .health_grace("1s")
        .launcher()?;
    let enrollment_path = dir.join("launcher-state/enrollment.json");
    let mut enrollment: updated_contracts::enrollment::EnrollmentBundle =
        serde_json::from_slice(&std::fs::read(&enrollment_path).map_err(str_err)?)
            .map_err(|error| error.to_string())?;
    enrollment.routing_root.push_str("tampered");
    std::fs::write(
        &enrollment_path,
        serde_json::to_vec(&enrollment).map_err(|error| error.to_string())?,
    )
    .map_err(str_err)?;
    let node = Service::spawn("bad-root", &cmd);
    if !wait_until(EVENT_TIMEOUT, || {
        node.captured_log()
            .contains("resolving signed managed configuration")
    }) {
        return fail(format!(
            "a tampered enrollment root did not produce a fail-closed result:\n{}",
            node.captured_log()
        ));
    }
    let log = node.captured_log();
    // Nothing authorized: no hook was ever invoked, so nothing the release could do was done.
    let ran_a_hook = !fixture::operations(&fixture::root(&dir)).is_empty();
    drop(node);
    fixture::stop_workload(&dir);
    if ran_a_hook || log.contains("upgraded to") {
        return fail(format!(
            "tampered enrollment trust authorized a reconciler invocation:\n{log}"
        ));
    }
    ok("tampered enrollment trust was rejected before any hook ran");
    Ok(())
}

pub(crate) fn signed_local_repair_without_network(ctx: &Ctx) -> R {
    let svc = "127.0.0.1:21140";
    let dir = ctx.work.join("signed-local-repair");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let v2 = app_v(ctx, "2.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;

    let node = Node::new(ctx, &dir, "127.0.0.1:1", "app")
        .local_repository()
        .check_interval("1s")
        .workload(svc)
        .health_grace("2s");
    let cmd = node.clone().launcher()?;
    let stack = Service::spawn("local-repair", &cmd);
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "the local baseline did not come into service:\n{}",
            stack.captured_log()
        ));
    }

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    republish_assignment(&node, "offline-repair")?;
    let active: updated::bundle::ReleaseId = serde_json::from_slice(
        &std::fs::read(node.install_root.join("active-release")).map_err(str_err)?,
    )
    .map_err(|error| error.to_string())?;
    let active_dir = std::fs::read_dir(node.install_root.join("versions"))
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
    drop(stack);
    fixture::stop_workload(&dir);
    make_owner_writable(&entrypoint)?;
    std::fs::write(&entrypoint, b"locally modified and no longer trusted").map_err(str_err)?;

    let repaired = Service::spawn("local-repair-restart", &cmd);
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "signed local repair did not replace the modified release without a server:\n{}",
            repaired.captured_log()
        ));
    }
    let log = repaired.captured_log();
    drop(repaired);
    fixture::stop_workload(&dir);
    if !log.contains("repaired the committed application from signed local deployment 2.0.0") {
        return fail(format!("the local repair path was not observed:\n{log}"));
    }
    ok("the modified release was replaced from a fully verified local signed deployment without network access, and the hook converged onto it");
    Ok(())
}
