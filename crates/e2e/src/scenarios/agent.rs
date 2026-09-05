use super::super::*;
use updated_contracts::reconciler::{Operation, Reason};

pub(crate) fn unhealthy_unconfirmed_release_rolls_back(ctx: &Ctx) -> R {
    let dir = ctx.work.join("unhealthy-confirmation");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    let command = Node::new(ctx, &dir, "127.0.0.1:21084", "app")
        .cold_install()
        .local_repository()
        .check_interval("1s")
        .health_grace("1s")
        .confirmation_window("12s")
        .mode("health-marker")
        .command()?;
    let node = Service::spawn("confirmation-health", &command);
    if !node.wait_for_log(
        "release 1.0.0 reached a confirmed installed state",
        EVENT_TIMEOUT,
    ) {
        return fail("initial release did not pass health");
    }
    std::fs::write(dir.join("assignment-addr"), "local").map_err(str_err)?;
    std::fs::write(
        dir.join("release-base-url"),
        format!("{}/", dir.join("release-repo").display()),
    )
    .map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let paths = node_paths(&dir);
    if !wait_until(EVENT_TIMEOUT, || {
        matches!(updated::state::read_installed(&paths.installed),
        updated::state::Installed::Present(ref state) if state.release.version == "2.0.0" && state.rollback_guard.is_some())
    }) {
        return fail("candidate was not committed with rollback protection");
    }
    std::fs::write(fixture::root(&dir).join("unhealthy"), b"fail v2 health").map_err(str_err)?;
    if !wait_until(EVENT_TIMEOUT, || {
        matches!(updated::state::read_installed(&paths.installed),
        updated::state::Installed::Present(ref state) if state.release.version == "1.0.0" && state.rollback_guard.is_none())
            && !paths.journal.exists()
    }) {
        return fail(format!(
            "unhealthy candidate did not roll back: {}",
            node.captured_log()
        ));
    }
    if node.captured_log().contains("update 2.0.0 confirmed") {
        return fail("the unhealthy candidate was confirmed");
    }
    Ok(())
}

pub(crate) fn routine_convergence_keeps_running_health_gates(ctx: &Ctx) -> R {
    let dir = ctx.work.join("routine-convergence-health");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    let command = Node::new(ctx, &dir, "127.0.0.1:21082", "app")
        .cold_install()
        .local_repository()
        .check_interval("1s")
        .health_grace("8s")
        .command()?;
    let node = Proc::spawn("routine-health", command)?;
    if !node.wait_for_log("boot health gate passed", EVENT_TIMEOUT) {
        return fail("the initial health gate did not pass");
    }
    let gated = wait_until(20, || {
        fixture::operations(&fixture::root(&dir))
            .iter()
            .filter(|invocation| {
                invocation.operation == Operation::Healthcheck
                    && invocation.id == updated_contracts::reconciler::attempt::CONVERGE
            })
            .count()
            >= 3
    });
    if !gated {
        return fail("routine convergence postponed health forever instead of gating each cycle");
    }
    Ok(())
}

/// The agent is disposable and the workload is not its to hold. Kill the agent outright: the
/// hook-managed workload keeps its PID and keeps answering, the service restarts the agent, and
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

    let command = Node::new(ctx, &dir, srv, "app")
        .health_grace("5s")
        .workload(svc)
        .command()?;
    let boot = Service::spawn("agent", &command);
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the release's converge hook never brought the workload into service");
    }
    let workload = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    let agent = pid_after(&boot.captured_log(), "service launched agent")
        .ok_or("the service never reported the agent PID it launched")?;
    let before = fixture::operations(&fixture::root(&dir)).len();

    // Crash ONLY the agent. Nothing in the workload's ancestry is touched: the reconciler put it in
    // a session of its own, exactly as an operator's init system would.
    kill_pid(agent);

    let relaunched = wait_until(EVENT_TIMEOUT, || {
        boot.log_count("service launched agent") >= 2
    });
    let resumed =
        relaunched && wait_until(EVENT_TIMEOUT, || boot.log_count("running packages in") >= 2);
    // The workload never noticed: same PID, still alive, still answering its own health endpoint.
    let undisturbed = pid_alive(workload)
        && fixture::workload_pid(&dir) == Some(workload)
        && http_text(&format!("http://{svc}/healthz")).is_some();

    // Completed entrypoints are not repeated on boot. The runtime observes actual health and
    // reuses its receipt; the workload must stay alive under the same PID.
    let re_converged = wait_until(EVENT_TIMEOUT, || {
        fixture::operations(&fixture::root(&dir))[before..]
            .iter()
            .any(|invocation| {
                invocation.operation == Operation::Healthcheck
                    && invocation.id == updated_contracts::reconciler::attempt::BOOT
            })
    });
    let disturbances = fixture::disturbances(&fixture::root(&dir), before);
    // Read the record before teardown removes it, so a failure reports what actually happened.
    let workload_after = fixture::workload_pid(&dir);
    let log = boot.captured_log();
    drop(boot);

    if !resumed {
        return fail(format!(
            "the service did not restart an agent that resumed reconciling:\n{log}"
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
    let mut converge_reason: Option<Reason> = None;
    for invocation in &fixture::operations(&fixture::root(&dir)) {
        if invocation.id != updated_contracts::reconciler::attempt::BOOT {
            continue;
        }
        match invocation.operation {
            Operation::Converge => converge_reason = Some(invocation.reason),
            Operation::Healthcheck if Some(invocation.reason) != converge_reason => {
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
        "an agent crash left the hook-managed workload untouched (pid {workload}); the service restarted the agent"
    ));
    Ok(())
}
