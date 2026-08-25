use super::super::*;

/// A cold node holds only the launcher and the agent. The agent installs the first trusted release
/// and the release's own `apply` hook starts its workload — the agent never launches a process.
pub(crate) fn cold_install_applies_the_first_release(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21079";
    let svc = "127.0.0.1:21074";
    let dir = ctx.work.join("cold-install");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let mut node = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .workload(svc)
        .check_interval("1s")
        .launcher()?;
    if node_paths(&dir).installed.exists() || node_paths(&dir).active_release.exists() {
        return fail("cold-install fixture accidentally contained a preinstalled application");
    }
    let process = Proc::spawn("cold-install", &mut node)?;
    let installed = process.wait_for_log(
        "cold-installed application 1.0.0 from the first trusted assignment",
        CONVERGE_TIMEOUT,
    ) && wait_for_version(svc, "1.0.0", CONVERGE_TIMEOUT)
        && node_paths(&dir).installed.is_file()
        && node_paths(&dir).active_release.is_file();
    let log = process.captured_log();
    drop(process);
    if !installed {
        return fail(format!(
            "the agent did not cold-install the first release and converge it through apply:\n{log}"
        ));
    }
    ok("a cold node installed the trusted bundle and the release's apply hook brought it into service");
    Ok(())
}
/// The install and update state machines share a node but never overlap. This cold-installs v1
/// through the install machine, proves it left NO install journal behind, then updates to v2
/// through the update machine — proving a clean handoff and that the two journals never coexist
/// or confuse each other. It is the interaction guarantee that `ensure_installed` documents.
pub(crate) fn cold_install_hands_off_to_update(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:22900", "127.0.0.1:22901");
    let dir = ctx.work.join("install-update-handoff");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let cmd = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .check_interval("2s")
        .health_grace("2s")
        .workload(svc)
        .launcher()?;
    let node = Service::spawn("handoff", &cmd);
    let fail_log = |msg: &str| -> R { fail(format!("{msg}\nlog:\n{}", node.captured_log())) };

    let install_journal = node_paths(&dir).install_journal;
    let update_journal = node_paths(&dir).journal;
    let installed = node_paths(&dir).installed;

    // Install machine: cold-install v1, then prove it converged and left NO install journal.
    if !node.wait_for_log(
        "cold-installed application 1.0.0 from the first trusted assignment",
        EVENT_TIMEOUT,
    ) || !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT)
    {
        return fail_log("install machine did not cold-install and converge v1.0.0");
    }
    if !wait_until(EVENT_TIMEOUT, || !install_journal.exists()) {
        return fail_log("install machine left its journal behind after committing");
    }

    // Update machine: publish v2; the agent loop takes over. Prove it converges to v2 and
    // leaves NEITHER journal behind — the two machines never coexisted on this node.
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail_log("update machine did not upgrade to v2.0.0 after the install handoff");
    }
    let converged = wait_until(EVENT_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&installed),
            updated::state::Installed::Present(ref s) if s.release.version == "2.0.0"
        ) && !install_journal.exists()
            && !update_journal.exists()
    });
    let log = node.captured_log();
    drop(node);
    if !converged {
        return fail(format!(
            "install/update handoff left durable state inconsistent (installed != 2.0.0, or a journal remained):\n{log}"
        ));
    }
    ok("install machine cold-installed v1, then the update machine upgraded to v2 with no journal overlap");
    Ok(())
}

pub(crate) fn app_update_and_rollback(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21080", "127.0.0.1:21090");
    let dir = ctx.work.join("app");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("2s")
        .health_grace("2s")
        // This scenario exercises two consecutive update edges. Keep the real
        // confirmation gate, but shorten its window so v3 is not published until the
        // v1 -> v2 edge has been confirmed.
        .confirmation_window("3s")
        .workload(svc)
        .launcher()?;
    // Under a simulated init system: a candidate that fails after activation is rolled back by
    // boot recovery on the next launch, not by an in-process rollback.
    let node = Service::spawn("node", &cmd);
    // On any failure, attach the node's captured log (launcher + agent). The install
    // state is already dumped by the runner, so between the two a hang or wrong-state is
    // diagnosable from the failure alone rather than needing a re-run.
    let fail_log = |msg: &str| -> R { fail(format!("{msg}\nlog:\n{}", node.captured_log())) };

    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail_log("the release's apply hook never brought v1.0.0 into service");
    }
    ok("v1.0.0 live from the TUF repository, started by the release's own hook");

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail_log("service did not upgrade to v2.0.0");
    }
    ok("unattended upgrade to v2.0.0");

    if !node.wait_for_log(
        "update 2.0.0 confirmed; confirmation window passed",
        EVENT_TIMEOUT,
    ) {
        return fail_log("v2.0.0 was not confirmed before the next update");
    }

    // A validly signed target whose entrypoint starts and immediately exits (the `server` binary
    // rejects the workload's args): a real swap whose candidate fails its health gate during
    // activation. The transaction rejects the crashing release and leaves a durable rollback
    // journal, then the disposable agent terminates so *boot recovery* restores v2 on the next
    // launch — the single rollback path. (An agent crash mid-transaction lands on the very same
    // recovery, which is what the chaos scenarios cover.)
    ctx.publish(&dir, "app", "3.0.0", &ctx.server.clone())?;
    // 1. The disposable agent defers the rollback to boot recovery and exits.
    if !node.wait_for_log(
        "update failed after activation; restarting so boot recovery rolls back",
        EVENT_TIMEOUT,
    ) {
        return fail_log("the failing v3.0.0 did not defer its rollback to boot recovery");
    }
    // 2. The relaunched agent rejects the bad bytes...
    if !node.wait_for_log(
        "recovery: rejected 3.0.0 after failed activation",
        EVENT_TIMEOUT,
    ) {
        return fail_log("boot recovery did not reject the failing v3.0.0");
    }
    // 3. ...and the predecessor's own apply hook puts v2.0.0 back into service.
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail_log("service did not recover to v2.0.0 after the failing v3.0.0");
    }
    let log = node.captured_log();
    drop(node);
    if !log.contains("restoring predecessor 2.0.0 after interrupted activation of 3.0.0")
        && !log.contains("recovery: completing rollback from 3.0.0 to 2.0.0")
    {
        return fail(format!("boot recovery did not roll back to v2.0.0:\n{log}"));
    }
    ok("broken v3.0.0 applied, failed its health gate, was rejected, and boot recovery restored v2.0.0");
    Ok(())
}

/// Zero downtime across an upgrade the RELEASE performs. The agent owns no workload process, so
/// there is nothing for it to drain: withdrawing the node from traffic before the old process is
/// stopped, and holding it out until the replacement answers, is the reconciler's own job. We prove
/// it by putting a stand-in load balancer in front — 15 clients that only send to a node its hook
/// says is in rotation — and requiring zero lost requests across the whole swap. An ordering bug
/// (stop first, withdraw after) shows up immediately as dropped requests, because the clients were
/// routed to a node that was still advertising itself as ready.
pub(crate) fn zero_downtime_upgrade(ctx: &Ctx) -> R {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let (srv, svc) = ("127.0.0.1:21150", "127.0.0.1:21151");
    let dir = ctx.work.join("zero-downtime");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace("2s")
        // The window the stand-in load balancer gets to observe the withdrawal. A worker is only
        // ever microseconds past its readiness check when it sends, so one second is orders of
        // magnitude more than the in-flight gap, while costing the upgrade a single second — the
        // scenario still fails outright if the ordering were stop-then-withdraw, because then no
        // hold length excuses a request sent to a node that was still in rotation.
        .draining_workload(svc, 1000)
        .launcher()?;
    let _node = Proc::spawn("zero-downtime", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("the release's apply hook never brought v1.0.0 into service");
    }
    if !wait_until(EVENT_TIMEOUT, || !fixture::draining(&dir)) {
        return fail("the hook never put v1.0.0 into rotation");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    let served = Arc::new(AtomicU64::new(0));
    let url = format!("http://{svc}/version");
    let workers: Vec<_> = (0..15)
        .map(|_| {
            let (stop, dropped, served, url, dir) = (
                stop.clone(),
                dropped.clone(),
                served.clone(),
                url.clone(),
                dir.clone(),
            );
            std::thread::spawn(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(2))
                    .build();
                while !stop.load(Ordering::Relaxed) {
                    // A load balancer only routes to a node in rotation; a draining node being
                    // skipped is correct removal, not a dropped request. A drained node is polled
                    // at the fixture's own rotation cadence rather than busy-waited: fifteen
                    // threads spinning on a stat would starve the very upgrade this scenario times.
                    // The served path takes no delay — request density is what makes a dropped
                    // request detectable.
                    if fixture::draining(&dir) {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    served.fetch_add(1, Ordering::Relaxed);
                    let ok = agent
                        .get(&url)
                        .call()
                        .ok()
                        .and_then(|response| response.into_string().ok())
                        .is_some_and(|body| body == "1.0.0" || body == "2.0.0");
                    // The PRE-request rotation gate above is the whole condition: a real LB had
                    // already routed this request. Rechecking afterwards would race the withdrawal
                    // and excuse exactly the stop-before-withdraw ordering bug this scenario exists
                    // to catch.
                    if !ok {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    std::thread::sleep(Duration::from_secs(2));
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let reached = wait_for_version(svc, "2.0.0", EVENT_TIMEOUT);
    // Rotation must come back on its own. The hook withdrew the node to swap the workload, and a
    // marker left behind would keep a healthy node out of service forever — so the swap is not
    // finished until the release says it is serving again.
    let rejoined = reached && wait_until(EVENT_TIMEOUT, || !fixture::draining(&dir));
    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.join();
    }

    if !reached {
        return fail("service did not upgrade to v2.0.0 under load");
    }
    if !rejoined {
        return fail("the hook withdrew the node for its swap and never put it back in rotation");
    }
    let (d, s) = (
        dropped.load(Ordering::Relaxed),
        served.load(Ordering::Relaxed),
    );
    if d != 0 {
        return fail(format!(
            "the hook's swap dropped {d} of {s} requests sent to a node in rotation — not zero-downtime"
        ));
    }
    ok(&format!(
        "the release's own upgrade drained cleanly: {s} requests to a node in rotation, 0 dropped across the swap"
    ));
    Ok(())
}

/// Exercise failures in the workload itself, observed the only way the agent can observe them:
/// through the release's `healthcheck` hook. These are real signed bundles and real localhost HTTP
/// exchanges; nothing is mocked.
///
/// The distinction the new crash evidence draws is the point. A provisional head that has NEVER
/// proven healthy is rejected, so a node is never stranded on it. A head that proved healthy once
/// and later degrades is REPORTED and kept — the reconciler owns the workload and may converge it,
/// and rejecting a release that already worked would fight it.
pub(crate) fn chaotic_application_health_failures(ctx: &Ctx) -> R {
    let cases = [
        ("exit-before-bind", 22100u16, false),
        ("unhealthy", 22101, false),
        ("hang-health", 22102, false),
        ("flapping", 22105, false),
        // Answers one probe and exits inside it: with two consecutive successes required, the
        // release is gone before it can prove itself.
        ("crash-on-health", 22106, false),
        // This one becomes ready and is confirmed first, then degrades.
        ("degrade-after-ready", 22107, true),
    ];

    for (fault, port, proves_healthy_first) in cases {
        let srv = format!("127.0.0.1:{}", port + 100);
        let svc = format!("127.0.0.1:{port}");
        let dir = ctx.work.join(format!("chaotic-health-{fault}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let _workload = fixture::workload(&dir);
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
        let _server = ctx.serve(&dir, &srv)?;
        let command = Node::new(ctx, &dir, &srv, "app")
            .cold_install()
            .check_interval("1s")
            .health_grace("4s")
            .health_successes(if matches!(fault, "flapping" | "crash-on-health") {
                2
            } else {
                1
            })
            .faulty_workload(&svc, fault)
            .launcher()?;
        let node = Service::spawn("chaotic-app", &command);
        let rejected = node_paths(&dir).rejected;

        let held = if proves_healthy_first {
            // It must first be proven — the gate passed and the head confirmed — and then stay
            // installed and unrejected as it degrades. A rejection here would condemn a release
            // that had already worked on this node.
            if !wait_for_version(&svc, "1.0.0", EVENT_TIMEOUT)
                || !wait_until(EVENT_TIMEOUT, || {
                    matches!(
                        updated::state::read_installed(&node_paths(&dir).installed),
                        updated::state::Installed::Present(ref state) if state.confirmed
                    )
                })
            {
                return fail(format!(
                    "fault {fault}: the release never reached its intentional initial healthy state:\n{}",
                    node.captured_log()
                ));
            }
            stays_true(READINESS_SETTLE, || {
                std::fs::read_to_string(&rejected)
                    .map(|text| text.trim().is_empty())
                    .unwrap_or(true)
            })
        } else {
            // A head that never proves healthy is rejected by the boot gate, so the node is free to
            // descend rather than serving something that does not work.
            node.wait_for_log(
                "the provisional head failed its boot health gate",
                EVENT_TIMEOUT,
            ) && wait_until(EVENT_TIMEOUT, || {
                std::fs::read_to_string(&rejected)
                    .map(|text| !text.trim().is_empty())
                    .unwrap_or(false)
            })
        };
        let log = node.captured_log();
        drop(node);
        if !held {
            return fail(format!(
                "fault {fault}: the healthcheck hook's verdict was not acted on as expected:\n{log}"
            ));
        }
        ok(&format!(
            "workload fault {fault} was handled by the healthcheck hook's verdict alone"
        ));
    }
    Ok(())
}

/// A stateless node whose *first* (cold) assignment is a broken head must not strand crash-looping
/// it. This is the pod-kill-onto-a-broken-rollout case: an emptyDir node returns cold with no
/// rejection history, cold-installs its assigned head, the release's own `apply` cannot start it —
/// and, because ordered-install fallback is signed in — rejects it and descends to the newest
/// healthy release below it. Two broken heads are stacked above the good 1.0.0, so recovery must
/// descend past BOTH. Run under the init model so the reject → descend cycle plays out exactly as it
/// would in a container whose state dir survives container restarts.
pub(crate) fn cold_install_descends_past_broken_head(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21230", "127.0.0.1:21231");
    let dir = ctx.work.join("cold-install-fallback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    // The good release below the broken heads.
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Two heads whose apply hook fails: bytes that verify and stage but whose entrypoint cannot
    // exec, exactly like the fleet e2e's broken rollout versions. The assigned head is the newest
    // (3.0.0), so recovery must descend past both 3.0.0 and 2.0.0 to reach the healthy 1.0.0.
    let broken = dir.join("broken-app");
    std::fs::write(&broken, b"not-a-runnable-application-entrypoint\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &broken)?;
    ctx.publish(&dir, "app", "3.0.0", &broken)?;
    let _server = ctx.serve(&dir, srv)?;
    let command = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .ordered_install_fallback()
        .workload(svc)
        .check_interval("1s")
        .health_grace("2s")
        .launcher()?;
    let node = Service::spawn("cold-install-fallback", &command);
    // Recovery is proven when the descended-to 1.0.0 actually serves — the node recovered rather
    // than crash-looping the broken head forever. A working descent takes a few boots (~30s); cap
    // the wait so a failure surfaces its rich per-attempt diagnostics quickly instead of hanging.
    if !wait_for_version(svc, "1.0.0", CONVERGE_TIMEOUT) {
        let log = node.captured_log();
        return fail(format!(
            "cold node stranded on a broken assigned head instead of descending to the healthy \
             1.0.0. Agent log (the 'no installable application' lines enumerate every \
             candidate and why each was skipped):\n{log}"
        ));
    }
    // Durability: the committed install record names the descended-to 1.0.0, so a further restart
    // converges 1.0.0 and never climbs back onto a rejected broken head.
    let settled = wait_for_installed_version(&dir, "1.0.0", CONVERGE_TIMEOUT);
    drop(node);
    if !settled {
        return fail(
            "descended app served 1.0.0 but the committed install record never settled on it",
        );
    }
    ok("a cold node rejected two assigned heads whose apply hook failed and descended to the healthy 1.0.0");
    Ok(())
}

/// Rejection is a fail-closed invariant even when ordered fallback has no lower release left.
/// Once the only signed deployment has failed its first health gate, later boots must stop with
/// diagnostics; they may never relaunch the rejected provisional head as an availability escape.
pub(crate) fn cold_install_fails_closed_when_every_candidate_is_rejected(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21630", "127.0.0.1:21631");
    let dir = ctx.work.join("cold-install-exhausted");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    let broken = dir.join("only-broken-app");
    std::fs::write(&broken, b"not-a-runnable-application-entrypoint\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "1.0.0", &broken)?;
    let _server = ctx.serve(&dir, srv)?;
    let command = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .ordered_install_fallback()
        .workload(svc)
        .check_interval("1s")
        .health_grace("2s")
        .launcher()?;
    let node = Service::spawn("cold-install-exhausted", &command);
    let failed_closed = node.wait_for_log(
        "the first trusted assignment contains no installable application",
        CONVERGE_TIMEOUT,
    );
    let remained_down = stays_true(READINESS_SETTLE, || {
        http_text(&format!("http://{svc}/version")).is_none()
    });
    let rejected = std::fs::read_to_string(node_paths(&dir).rejected).unwrap_or_default();
    let log = node.captured_log();
    drop(node);
    if !failed_closed || !remained_down || rejected.trim().is_empty() {
        return fail(format!(
            "an exhausted cold-install fallback did not fail closed (diagnostic={failed_closed}, \
             stayed_down={remained_down}, rejection_recorded={}):\n{log}",
            !rejected.trim().is_empty()
        ));
    }
    ok("a cold node with no healthy fallback kept the rejected deployment down and emitted complete selection diagnostics");
    Ok(())
}

/// A cold node whose assigned head is a *malformed* bundle — one that verifies its signed archive
/// hash but cannot be extracted or validated (a corrupt or truncated tar.zst, not merely a bad
/// entrypoint) — must reject it at ingest and descend, exactly like a head whose apply fails. Two
/// distinct corruption kinds are stacked above the healthy 1.0.0, so ordered fallback must reject
/// two independent malformed hashes *before any hook runs* and land on 1.0.0. This guards the
/// cold-install analogue of the update path's malformed-bundle rejection, which previously did not
/// exist — a cold node re-downloaded a malformed head forever instead of descending past it.
pub(crate) fn cold_install_descends_past_corrupt_bundle(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21530", "127.0.0.1:21531");
    let dir = ctx.work.join("cold-install-corrupt");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Malformed-but-signed heads: 2.0.0 truncated, 3.0.0 pure garbage. Each verifies its signed
    // archive hash yet fails to extract, so it is rejected at ingest by content hash — before any
    // hook runs — and the descent must step past both.
    // The sample binary is version-agnostic (version is stamped into the bundle by the publisher)
    // and the archive is corrupted anyway, so any built source works; only 1.0.0/2.0.0 are built.
    ctx.publish_corrupt(&dir, "app", "2.0.0", &app_v(ctx, "1.0.0"), "truncate")?;
    ctx.publish_corrupt(&dir, "app", "3.0.0", &app_v(ctx, "1.0.0"), "garbage")?;
    let _server = ctx.serve(&dir, srv)?;
    let command = Node::new(ctx, &dir, srv, "app")
        .cold_install()
        .ordered_install_fallback()
        .workload(svc)
        .check_interval("1s")
        .health_grace("2s")
        .launcher()?;
    let node = Service::spawn("cold-install-corrupt", &command);
    // The malformed heads are rejected at ingest (no hook), so the descent is fast; keep a
    // generous cap so a regression surfaces its diagnostics instead of hanging.
    if !wait_for_version(svc, "1.0.0", CONVERGE_TIMEOUT) {
        let log = node.captured_log();
        return fail(format!(
            "cold node stranded on a malformed assigned bundle instead of rejecting it at ingest \
             and descending to the healthy 1.0.0:\n{log}"
        ));
    }
    let settled = wait_for_installed_version(&dir, "1.0.0", CONVERGE_TIMEOUT);
    let rejected = std::fs::read_to_string(node_paths(&dir).rejected).unwrap_or_default();
    let rejected_count = rejected.lines().filter(|l| !l.trim().is_empty()).count();
    drop(node);
    if !settled {
        return fail(
            "descended app served 1.0.0 but the committed install record never settled on it",
        );
    }
    if rejected_count < 2 {
        return fail(format!(
            "expected both malformed heads recorded rejected; saw {rejected_count}:\n{rejected}"
        ));
    }
    ok("cold node rejected two malformed-but-signed assigned bundles at ingest and ordered fallback descended to the healthy 1.0.0");
    Ok(())
}

/// The crash-evidence semantics, both halves in one node.
///
/// The agent has no workload process to watch, so the only evidence it ever has about a release is
/// what the `healthcheck` hook says at a boot gate. What it does with that evidence depends
/// entirely on whether the release has ever proven itself:
///
/// * An UNCONFIRMED release — still inside its confirmation window — is reverted to its predecessor
///   and its bytes rejected. One strike, and the failure a finite health window cannot catch.
/// * A CONFIRMED release is only REPORTED. It proved healthy once, its reconciler owns the workload
///   and may converge it later, and there is no predecessor image left to revert to.
///
/// The failure both halves use is a release that passes its first health observation and fails every
/// one after it. That, and not a killed process, is what the evidence has to be built from: a
/// reconciler that owns its workload restarts a process that merely died — the boot converge's
/// `apply` would heal it before the gate ever ran — so "the workload is gone" is not by itself
/// evidence of anything. A release that is running and unhealthy is.
pub(crate) fn crash_evidence_reverts_only_the_unconfirmed(ctx: &Ctx) -> R {
    // Half one: a still-unconfirmed 2.0.0 whose workload dies is reverted and rejected.
    let (srv, svc) = ("127.0.0.1:21089", "127.0.0.1:21099");
    let dir = ctx.work.join("crash-evidence-unconfirmed");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("2s")
        .health_grace("2s")
        .hold_unconfirmed()
        .faulty_workload(svc, "degrade-after-ready")
        .launcher()?;
    let node = Service::spawn("unconfirmed", &cmd);
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("v1.0.0 never came into service");
    }
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    // Let the candidate commit first: it passes its transaction health gate on its first
    // observation and degrades immediately afterwards.
    if !node.wait_for_log("upgraded to 2.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "the degrading v2.0.0 never committed:\n{}",
            node.captured_log()
        ));
    }
    // The agent has no process to watch: the evidence only arrives at the next boot's gate, so
    // crash the agent (the launcher relaunches it) to reach one.
    let agent = pid_after(&node.captured_log(), "launched agent")
        .ok_or("the launcher never reported the agent PID")?;
    kill_pid(agent);
    let reverted = node.wait_for_log(
        "failed its boot health gate inside its confirmation window; reverting to 1.0.0",
        EVENT_TIMEOUT,
    ) && wait_for_version(svc, "1.0.0", EVENT_TIMEOUT);
    let rejected = std::fs::read_to_string(node_paths(&dir).rejected).unwrap_or_default();
    let log = node.captured_log();
    drop(node);
    if !reverted {
        return fail(format!(
            "an unconfirmed release whose workload died was not reverted to 1.0.0:\n{log}"
        ));
    }
    if rejected.trim().is_empty() {
        return fail("the reverted release's hash was not rejected");
    }
    ok("an unconfirmed release that failed its boot health gate was reverted and rejected (one strike)");

    // Half two: the same failure against a CONFIRMED release is reported, never reverted.
    let (srv, svc) = ("127.0.0.1:21189", "127.0.0.1:21199");
    let dir = ctx.work.join("crash-evidence-confirmed");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("2s")
        .health_grace("2s")
        .confirmation_window("2s")
        .faulty_workload(svc, "degrade-after-ready")
        .launcher()?;
    let node = Service::spawn("confirmed", &cmd);
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("v1.0.0 never came into service");
    }
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    if !node.wait_for_log(
        "update 2.0.0 confirmed; confirmation window passed",
        EVENT_TIMEOUT,
    ) {
        return fail(format!(
            "v2.0.0 was never confirmed:\n{}",
            node.captured_log()
        ));
    }
    let agent = pid_after(&node.captured_log(), "launched agent")
        .ok_or("the launcher never reported the agent PID")?;
    kill_pid(agent);
    let reported = node.wait_for_log(
        "the committed release 2.0.0 is unhealthy; reporting it and continuing to reconcile",
        EVENT_TIMEOUT,
    );
    // Never reverted and never rejected: the committed record still names 2.0.0.
    let held = reported
        && stays_true(READINESS_SETTLE, || {
            matches!(
                updated::state::read_installed(&node_paths(&dir).installed),
                updated::state::Installed::Present(ref state) if state.release.version == "2.0.0"
            ) && std::fs::read_to_string(node_paths(&dir).rejected)
                .map(|text| text.trim().is_empty())
                .unwrap_or(true)
        });
    let log = node.captured_log();
    drop(node);
    if !held {
        return fail(format!(
            "a confirmed release that became unhealthy was not merely reported (reported={reported}):\n{log}"
        ));
    }
    ok("a confirmed release that became unhealthy was reported and kept, never reverted locally");
    Ok(())
}

pub(crate) fn group_peer_failure_is_node_local(ctx: &Ctx) -> R {
    let root = ctx.work.join("group-peer-isolation");
    let v1 = app_v(ctx, "1.0.0");
    let v2 = app_v(ctx, "2.0.0");
    let nodes = [
        ("healthy", "127.0.0.1:21120", "127.0.0.1:21130", false),
        ("failing", "127.0.0.1:21121", "127.0.0.1:21131", true),
    ];
    // Drop order is intentional: stop each node first, then its repository, and only then the
    // hook-managed workloads. This keeps teardown from generating transport failures or killing a
    // workload before the node stack has stopped observing it.
    let mut workloads = Vec::new();
    let mut servers = Vec::new();
    let mut services = Vec::new();

    for (name, repository_addr, service_addr, fails) in nodes {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        workloads.push(fixture::workload(&dir));
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        servers.push(ctx.serve(&dir, repository_addr)?);

        // The failing peer keeps a long window so its update is still unconfirmed when its release
        // degrades; the healthy peer's short window lets it settle.
        let mut node = Node::new(ctx, &dir, repository_addr, "app")
            .check_interval("1s")
            .health_grace("2s");
        node = if fails {
            node.hold_unconfirmed()
        } else {
            node.confirmation_window("8s")
        };
        // Only the failing peer's release degrades after its first health observation; the two
        // nodes are otherwise identical, so what separates them is the release's own health.
        node = if fails {
            node.faulty_workload(service_addr, "degrade-after-ready")
        } else {
            node.workload(service_addr)
        };
        let command = node.launcher()?;
        services.push((dir, service_addr, Service::spawn(name, &command)));
    }

    for (_, address, _) in &services {
        if !wait_for_version(address, "1.0.0", EVENT_TIMEOUT) {
            return fail(format!("node at {address} did not start at 1.0.0"));
        }
    }
    for (dir, _, _) in &services {
        ctx.publish(dir, "app", "2.0.0", &v2)?;
    }
    if !wait_for_version("127.0.0.1:21130", "2.0.0", EVENT_TIMEOUT) {
        return fail("healthy peer did not commit 2.0.0");
    }
    let (_, failing_addr, failing) = &services[1];
    if !failing.wait_for_log("upgraded to 2.0.0", EVENT_TIMEOUT) {
        return fail(format!(
            "the failing peer never committed its degrading v2.0.0:\n{}",
            failing.captured_log()
        ));
    }
    let agent = pid_after(&failing.captured_log(), "launched agent")
        .ok_or("the failing peer's launcher never reported an agent PID")?;
    kill_pid(agent);
    if !failing.wait_for_log(
        "failed its boot health gate inside its confirmation window; reverting to 1.0.0",
        EVENT_TIMEOUT,
    ) || !wait_for_version(failing_addr, "1.0.0", EVENT_TIMEOUT)
    {
        return fail(format!(
            "failing peer did not roll back to 1.0.0:\n{}",
            failing.captured_log()
        ));
    }
    if !services[0].2.wait_for_log(
        "update 2.0.0 confirmed; confirmation window passed",
        EVENT_TIMEOUT,
    ) || !wait_for_version("127.0.0.1:21130", "2.0.0", EVENT_TIMEOUT)
    {
        return fail("healthy peer was incorrectly rolled back with its failing peer");
    }
    ok("one node reverted locally while its group peer remained committed at 2.0.0");
    Ok(())
}
