use super::super::*;
use updated_contracts::reconciler::Operation;
pub(crate) fn single_instance_lock(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21082", "127.0.0.1:21092");
    let dir = ctx.work.join("lock");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let v1 = app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    // Prepare the node once so testing lock contention cannot also reconfigure the owner.
    let command = Node::new(ctx, &dir, srv, "app")
        .health_grace("2s")
        .workload(svc)
        .command()?;
    let first = Service::spawn("agent-1", &command);
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the first agent never converged its release");
    }
    let workload = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    let operations = fixture::operations(&fixture::root(&dir)).len();

    let second = Service::spawn("agent-2", &command);
    if !second.wait_for_log("already owns this install", EVENT_TIMEOUT) {
        return fail("the second agent was not refused with the expected lock message");
    }
    let second_log = second.captured_log();
    // The refused agent must die on the instance lock before it boot-converges. The owner keeps
    // recording its own steady-state observations while we watch, so the assertion is not "the log
    // never grew" — it is that nothing a REFUSED agent would produce appears: its first invocation
    // would be the boot converge's `converge`, and everything the owner legitimately appends in steady
    // state is a reserved-identity observation.
    let only_owner_observations = fixture::operations(&fixture::root(&dir))[operations..]
        .iter()
        .all(|invocation| {
            matches!(
                invocation.operation,
                Operation::Healthcheck | Operation::Inspect
            ) && updated_contracts::reconciler::attempt::is_reserved(&invocation.id)
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
