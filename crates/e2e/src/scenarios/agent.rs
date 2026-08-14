use super::super::*;

/// The agent is disposable and the workload is not its to hold. Kill the agent outright: the
/// hook-managed workload keeps its PID and keeps answering, the launcher relaunches the agent, and
/// the new agent resumes reconciling without running a single deployment operation — the boot
/// converge finds the workload already correct and leaves it strictly alone.
///
/// This is the whole package-runner claim in one scenario. The agent has no means to disturb a
/// workload (it holds no PID, no process group, no handle), so the proof is not that it chose not
/// to but that nothing changed while it died and came back.
pub(crate) fn agent_crash_never_disturbs_the_workload(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21081", "127.0.0.1:21091");
    let dir = ctx.work.join("agent-crash");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let v1 = app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let boot = Proc::spawn(
        "launcher",
        &mut Node::new(ctx, &dir, srv, "app")
            .health_grace("5s")
            .workload(svc)
            .launcher()?,
    )?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the release's apply hook never brought the workload into service");
    }
    let workload = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    let agent = pid_after(&boot.captured_log(), "launched agent")
        .ok_or("the launcher never reported the agent PID it launched")?;
    let before = fixture::operations(&fixture::root(&dir)).len();

    // Crash ONLY the agent. Nothing in the workload's ancestry is touched: the reconciler put it in
    // a session of its own, exactly as an operator's init system would.
    kill_pid(agent);

    let relaunched = wait_until(EVENT_TIMEOUT, || boot.log_count("launched agent") >= 2);
    let resumed =
        relaunched && wait_until(EVENT_TIMEOUT, || boot.log_count("running packages in") >= 2);
    // The workload never noticed: same PID, still alive, still answering its own health endpoint.
    let undisturbed = pid_alive(workload)
        && fixture::workload_pid(&dir) == Some(workload)
        && http_text(&format!("http://{svc}/healthz")).is_some();

    // And the recovered agent disturbed nothing: no deployment operation and no `rollback` — only
    // the reserved-identity invocations a boot legitimately makes. The other half of the claim is
    // that it really did re-converge: the boot `apply` is present, under `--reason restart`, and it
    // changed nothing, which is the whole package-runner point.
    let boot_converges = |slice: &[fixture::Invocation]| {
        slice
            .iter()
            .filter(|invocation| {
                invocation.operation == "apply"
                    && invocation.id == updated_contracts::reconciler::attempt::BOOT
            })
            .count()
    };
    // The reserved identity is a deliberately recurring name, never an idempotency key: EVERY boot
    // runs the converge under it. So the count grows with each boot — one before the crash, at
    // least one more after. "Resumed reconciling" (above) is the agent's banner, which lands
    // BEFORE its boot converge runs, so the recorded history is given the same bounded wait as
    // every other eventually-true observation rather than one sample under a loaded runner.
    let re_converged = wait_until(EVENT_TIMEOUT, || {
        let added = fixture::operations(&fixture::root(&dir));
        boot_converges(&added[..before]) >= 1 && boot_converges(&added[before..]) >= 1
    });
    let disturbances = fixture::disturbances(&fixture::root(&dir), before);
    // Read the record before teardown removes it, so a failure reports what actually happened.
    let workload_after = fixture::workload_pid(&dir);
    let log = boot.captured_log();
    drop(boot);

    if !resumed {
        return fail(format!(
            "the launcher did not relaunch an agent that resumed reconciling:\n{log}"
        ));
    }
    if !undisturbed {
        return fail(format!(
            "the agent crash disturbed the hook-managed workload (pid {workload} was {workload_after:?} afterwards)"
        ));
    }
    if !disturbances.is_empty() {
        return fail(format!(
            "the recovered agent reached for the workload: {}",
            disturbances.join(", ")
        ));
    }
    if !re_converged {
        return fail(
            "each boot must run its own converge under the reserved boot identity, and this run \
             did not: nothing proves the converge is what left the workload alone",
        );
    }
    // The boot converge and the boot gate belong to the same boot, so they carry the same
    // `--reason` — `install` on the first boot, `restart` afterwards — and never `update`. A gate
    // that invents its own reason contradicts the converge that just ran.
    let mut converge_reason = String::new();
    for invocation in &fixture::operations(&fixture::root(&dir)) {
        if invocation.id != updated_contracts::reconciler::attempt::BOOT {
            continue;
        }
        match invocation.operation.as_str() {
            "apply" => converge_reason = invocation.reason.clone(),
            "healthcheck" if invocation.reason != converge_reason => {
                return fail(format!(
                    "the boot gate was invoked with --reason {} while its boot converge ran with \
                     --reason {converge_reason:?}",
                    invocation.reason
                ));
            }
            _ => {}
        }
    }
    ok(&format!(
        "an agent crash left the hook-managed workload untouched (pid {workload}); the launcher relaunched the agent"
    ));
    Ok(())
}
