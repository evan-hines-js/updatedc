use super::super::*;
pub(crate) fn persisted_rejection(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21084", "127.0.0.1:21094");
    let dir = ctx.work.join("reject");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    // Broken v2: the `server` binary starts and immediately exits on the workload's args, so the
    // release's healthcheck can never pass.
    ctx.publish(&dir, "app", "2.0.0", &ctx.server.clone())?;
    let _server = ctx.serve(&dir, srv)?;

    let make = || {
        Node::new(ctx, &dir, srv, "app")
            .check_interval("1s")
            .health_grace("1s")
            .workload(svc)
            .launcher()
    };

    // Run 1: apply the broken v2. Its health gate fails, the transaction leaves a durable rollback
    // journal and ends the disposable agent; the init system relaunches the stack and boot recovery
    // rejects v2 and restores v1 — persisting the rejection so the failed bytes are never
    // re-applied.
    {
        let cmd = make()?;
        let node = Service::spawn("reject-1", &cmd);
        if !node.wait_for_log(
            "recovery: rejected 2.0.0 after failed activation",
            EVENT_TIMEOUT,
        ) {
            return fail(format!(
                "boot recovery did not reject the broken v2:\n{}",
                node.captured_log()
            ));
        }
        if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
            return fail(format!(
                "the node did not recover to v1.0.0 after rejecting v2:\n{}",
                node.captured_log()
            ));
        }
        let persisted = wait_until(EVENT_TIMEOUT, || {
            std::fs::metadata(dir.join("install/state/rejected"))
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        });
        if !persisted {
            return fail("the rejection was not persisted to disk");
        }
    }
    // End the first run's workload before the second stack reuses its address.
    fixture::stop_workload(&dir);
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/version")).is_none()
    }) {
        return fail("the first run's workload never released its address");
    }

    // Run 2 (a fresh stack): must NOT reapply the known-bad v2.
    {
        let cmd = make()?;
        let node = Service::spawn("reject-2", &cmd);
        if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
            return fail("v1.0.0 did not come back up on restart");
        }
        std::thread::sleep(Duration::from_secs(4));
        if node.log_contains("applying update 1.0.0 -> 2.0.0") {
            return fail("the restart re-applied the known-bad v2");
        }
    }
    fixture::stop_workload(&dir);
    ok("a release that failed its health gate was rejected on recovery and NOT reapplied after a restart");
    Ok(())
}
