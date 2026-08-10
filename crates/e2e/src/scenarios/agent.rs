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
        fixture::stop_workload(&dir);
        return fail("the release's apply hook never brought the workload into service");
    }
    let workload = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    let agent = pid_after(&boot.captured_log(), "launched agent")
        .ok_or("the launcher never reported the agent PID it launched")?;
    let before = fixture::attempts(&fixture::root(&dir)).len();

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

    // And the recovered agent ran no deployment operation at all. Its boot converge is an
    // ordinary reserved-identity invocation (never recorded as an attempt), and it converged onto
    // a workload that was already correct.
    let no_deployment_operations = fixture::attempts(&fixture::root(&dir)).len() == before;
    // Read the record before teardown removes it, so a failure reports what actually happened.
    let workload_after = fixture::workload_pid(&dir);
    let log = boot.captured_log();
    drop(boot);
    fixture::stop_workload(&dir);

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
    if !no_deployment_operations {
        return fail("the recovered agent ran a deployment operation it had no reason to run");
    }
    ok(&format!(
        "an agent crash left the hook-managed workload untouched (pid {workload}); the launcher relaunched the agent"
    ));
    Ok(())
}
