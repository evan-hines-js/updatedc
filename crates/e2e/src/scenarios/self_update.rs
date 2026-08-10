use super::super::*;

/// The node stack for the self-update scenarios: the launcher runs agent v1, which self-updates
/// from the `supervisor` TUF product while the release's own hook manages the workload.
fn node(ctx: &Ctx, dir: &Path, srv: &str, svc: &str, agent_v1: &Path) -> R<Command> {
    Node::new(ctx, dir, srv, "app")
        .workload(svc)
        .health_grace("3s")
        .supervisor_check_interval("1s")
        .ready_timeout("15")
        .supervisor_bin(agent_v1)
        .launcher()
}

/// Read the launcher's frozen pointer format rather than treating its header and path
/// as one filesystem path. This deliberately mirrors the public on-disk contract the
/// E2E test is meant to verify, without reaching into the launcher's private module.
fn desired_agent(dir: &Path) -> R<PathBuf> {
    let pointer = dir.join("launcher-state/desired-supervisor");
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

/// What a hook-managed workload looks like right now, for the before/after comparison every
/// self-update scenario makes: its PID, and how many deployment operations the reconciler has run.
///
/// A handoff must move neither. The agent's own boots legitimately invoke the reserved
/// `boot`/`periodic` observations (that is how it reports health at all), but a deployment
/// operation during a self-update would mean the agent had reached for the workload.
fn workload_state(dir: &Path) -> R<(u32, usize)> {
    let pid = fixture::workload_pid(dir).ok_or("the reconciler recorded no workload PID")?;
    if !pid_alive(pid) {
        return fail(format!(
            "the hook-managed workload (pid {pid}) is no longer running"
        ));
    }
    Ok((pid, fixture::attempts(&fixture::root(dir)).len()))
}

/// The launcher commits a self-updated agent (v1 → v2) by pointer flip, and the hook-managed
/// workload is never disturbed — the agent has no means to touch it across the whole handoff.
pub(crate) fn supervisor_self_update(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21086", "127.0.0.1:21096");
    let dir = ctx.work.join("selfupd");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let agent_v1 = supervisor_v(ctx, "1.0.0");

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // The agent is its own TUF product; 1.0.0 is the running build.
    ctx.publish(&dir, "supervisor", "1.0.0", &agent_v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let boot = Proc::spawn("launcher", &mut node(ctx, &dir, srv, svc, &agent_v1)?)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        fixture::stop_workload(&dir);
        return fail("the workload never came up under the node stack");
    }
    let (pid, operations) = workload_state(&dir)?;
    ok("node stack up on agent 1.0.0; the hook's workload is live");

    // Publish agent 2.0.0 (different bytes). The running agent stages it, hands its path to the
    // launcher, and exits; the launcher activates it under a readiness gate, the new agent proves
    // ready, and the launcher commits the desired-supervisor pointer.
    ctx.publish(&dir, "supervisor", "2.0.0", &supervisor_v(ctx, "2.0.0"))?;
    let committed = boot.wait_for_log("committed as the agent", EVENT_TIMEOUT);
    let (pid_after_update, operations_after) = workload_state(&dir)?;
    let undisturbed = committed && pid_after_update == pid && operations_after == operations;
    let desired = desired_agent(&dir)?;
    let log = boot.captured_log();
    drop(boot);
    fixture::stop_workload(&dir);

    if !committed {
        return fail(format!(
            "the launcher did not commit the self-updated agent 2.0.0:\n{log}"
        ));
    }
    if !undisturbed {
        return fail(format!(
            "the self-update reached the workload (pid {pid} -> {pid_after_update}, \
             {} deployment operation(s) during the handoff)",
            operations_after - operations
        ));
    }
    // The committed pointer must name the exact published v2 bytes. Comparing content
    // makes this separator-independent and proves more than a path substring does.
    let expected_v2_sha = sha256_hex(&supervisor_v(ctx, "2.0.0"))?;
    if !desired.is_file() || sha256_hex(&desired)? != expected_v2_sha {
        return fail(format!(
            "desired-supervisor did not advance to the staged v2 binary: {desired:?}"
        ));
    }
    ok(&format!(
        "the agent self-updated 1.0.0 -> 2.0.0 by pointer flip; the hook's workload kept running (pid {pid})"
    ));
    Ok(())
}

/// An agent candidate that cannot execute at all is rolled back by the launcher (the desired
/// pointer stays put), rejected by the agent, and never retried. The hook-managed workload is
/// untouched throughout — the failure in-process recovery could not survive.
pub(crate) fn supervisor_self_update_rollback(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21087", "127.0.0.1:21097");
    let dir = ctx.work.join("selfupd-rollback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let agent_v1 = supervisor_v(ctx, "1.0.0");

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "supervisor", "1.0.0", &agent_v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let boot = Proc::spawn("launcher", &mut node(ctx, &dir, srv, svc, &agent_v1)?)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        fixture::stop_workload(&dir);
        return fail("the workload never came up under the node stack");
    }
    let (pid, operations) = workload_state(&dir)?;
    ok("node stack up on agent 1.0.0; the hook's workload is live");

    // Publish an agent "2.0.0" whose bytes cannot execute. The running agent stages and
    // hash-verifies it (TUF only attests the bytes) and hands it off; the launcher cannot launch
    // the candidate, rolls the pointer back, and marks it; the agent rejects the hash and never
    // re-stages it.
    let broken = dir.join("broken-agent");
    std::fs::write(&broken, b"NOT-A-RUNNABLE-AGENT-BINARY\n").map_err(str_err)?;
    ctx.publish(&dir, "supervisor", "2.0.0", &broken)?;

    let rejected = boot.wait_for_log("rejecting", EVENT_TIMEOUT);
    let recorded = boot.wait_for_log("recorded rejected supervisor candidate", EVENT_TIMEOUT);
    // "Never retried" is a counting claim, so count. Snapshot both rejection tallies, then let
    // several agent check intervals (1s each here) elapse: an agent that forgot the rejected hash
    // would re-stage the same broken 2.0.0 every interval and both tallies would climb, while
    // every other assertion below — pointer, PID, served version — stayed green.
    let rejections = boot.log_count("rejecting");
    let records = boot.log_count("recorded rejected supervisor candidate");
    std::thread::sleep(Duration::from_secs(6));
    let retries = boot.log_count("rejecting") - rejections;
    let re_records = boot.log_count("recorded rejected supervisor candidate") - records;
    let served = wait_for_version(svc, "1.0.0", EVENT_TIMEOUT);
    let (pid_after_rollback, operations_after) = workload_state(&dir)?;
    let desired = desired_agent(&dir)?;
    let log = boot.captured_log();
    drop(boot);
    fixture::stop_workload(&dir);

    if !rejected {
        return fail(format!(
            "the launcher did not roll back the unlaunchable agent candidate:\n{log}"
        ));
    }
    if !served || pid_after_rollback != pid || operations_after != operations {
        return fail(format!(
            "the failed self-update reached the workload (pid {pid} -> {pid_after_rollback}, \
             {} deployment operation(s) during the handoff)",
            operations_after - operations
        ));
    }
    if !recorded {
        return fail("the failed candidate was not recorded as rejected by the agent");
    }
    if retries > 0 || re_records > 0 {
        return fail(format!(
            "the rejected agent candidate was re-staged after rejection ({retries} further rejections, {re_records} further rejection records in 6s)"
        ));
    }
    // The pointer must still resolve to the exact v1 bytes, irrespective of Windows
    // versus Unix path separators. A substring test could silently pass on Windows.
    if !desired.is_file() || sha256_hex(&desired)? != sha256_hex(&agent_v1)? {
        return fail(format!(
            "desired-supervisor did not remain on the committed v1 binary: {desired:?}"
        ));
    }
    ok("an unlaunchable agent candidate was rolled back, rejected, and never retried; the hook's workload was untouched");
    Ok(())
}

/// A candidate can pass its startup/readiness gate and still die immediately afterward.
/// The launcher must keep the predecessor pointer until the independent stability window
/// completes, reject this candidate, and leave the hook-managed workload untouched.
pub(crate) fn supervisor_post_ready_crash_rolls_back(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21122", "127.0.0.1:21123");
    let dir = ctx.work.join("selfupd-post-ready-crash");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let agent_v1 = supervisor_v(ctx, "1.0.0");
    let unstable = ctx.work.join(format!(
        "build/supervisor-post-ready-crash-2.0.0{}",
        ctx.exe
    ));

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "supervisor", "1.0.0", &agent_v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let boot = Proc::spawn("launcher", &mut node(ctx, &dir, srv, svc, &agent_v1)?)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        fixture::stop_workload(&dir);
        return fail("the node stack did not establish its baseline");
    }
    let (pid, operations) = workload_state(&dir)?;

    ctx.publish(&dir, "supervisor", "2.0.0", &unstable)?;
    let began_confirmation = boot.wait_for_log("beginning its confirmation window", EVENT_TIMEOUT);
    let rejected = boot.wait_for_log("exited; rolling back and rejecting it", EVENT_TIMEOUT);
    let predecessor_returned =
        boot.wait_for_log("recorded rejected supervisor candidate", EVENT_TIMEOUT);
    let still_serving = wait_for_version(svc, "1.0.0", EVENT_TIMEOUT);
    let (pid_after_crash, operations_after) = workload_state(&dir)?;
    let desired = desired_agent(&dir)?;
    let log = boot.captured_log();
    drop(boot);
    fixture::stop_workload(&dir);

    if !began_confirmation || !rejected || !predecessor_returned {
        return fail(format!(
            "the post-ready agent failure did not complete its guarded rollback:\n{log}"
        ));
    }
    if !still_serving || pid_after_crash != pid || operations_after != operations {
        return fail(format!(
            "the post-ready agent failure reached the workload (pid {pid} -> {pid_after_crash}, \
             {} deployment operation(s) during the handoff)",
            operations_after - operations
        ));
    }
    if !desired.is_file() || sha256_hex(&desired)? != sha256_hex(&agent_v1)? {
        return fail("the unstable ready agent was incorrectly committed");
    }
    ok("a post-ready agent crash rolled back before commit; the hook's workload never noticed");
    Ok(())
}
