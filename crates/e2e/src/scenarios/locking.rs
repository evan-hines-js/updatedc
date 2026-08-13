use super::super::*;
pub(crate) fn single_instance_lock(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21082", "127.0.0.1:21092");
    let dir = ctx.work.join("lock");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let v1 = app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut first_cmd = Node::new(ctx, &dir, srv, "app")
        .health_grace("2s")
        .workload(svc)
        .launcher()?;
    let first = Proc::spawn("agent-1", &mut first_cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the first agent never converged its release");
    }
    let workload = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    let operations = fixture::operations(&fixture::root(&dir)).len();

    // The second instance uses the SAME configuration as the first. Building a Node command
    // republishes the node's signed assignment (harness setup), so a *different* configuration here
    // would republish an assignment whose runtime changed — which the live first agent correctly
    // picks up and re-converges on, disturbing the owner via legitimate reassignment rather than the
    // lock we are testing. Identical settings make that republish a no-op, isolating the instance
    // lock, which is asserted directly below.
    let second_cmd = Node::new(ctx, &dir, srv, "app")
        .health_grace("2s")
        .workload(svc)
        .launcher()?;
    let second = Service::spawn("agent-2", &second_cmd);
    if !second.wait_for_log("already owns this install", EVENT_TIMEOUT) {
        return fail("the second agent was not refused with the expected lock message");
    }
    let second_log = second.captured_log();
    // The refused agent must die on the instance lock before it boot-converges. The owner keeps
    // recording its own steady-state observations while we watch, so the assertion is not "the log
    // never grew" — it is that nothing a REFUSED agent would produce appears: its first invocation
    // would be the boot converge's `apply`, and everything the owner legitimately appends in steady
    // state is a reserved-identity observation.
    let only_owner_observations = fixture::operations(&fixture::root(&dir))[operations..]
        .iter()
        .all(|invocation| {
            matches!(invocation.operation.as_str(), "healthcheck" | "inspect")
                && updated_contracts::reconciler::attempt::is_reserved(&invocation.id)
        });
    let owner_intact = wait_for_version(svc, "1.0.0", EVENT_TIMEOUT)
        && pid_alive(workload)
        && fixture::workload_pid(&dir) == Some(workload)
        && only_owner_observations;
    drop(second);
    drop(first);
    if !owner_intact {
        return fail(format!(
            "the lock rejection disturbed the owner's workload:\n{second_log}"
        ));
    }
    ok("a second agent on the same install was refused by the instance lock, and the owner's workload never moved");
    Ok(())
}
