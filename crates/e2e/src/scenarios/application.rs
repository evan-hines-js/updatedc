use super::super::*;

pub(crate) fn bootstrap_cold_installs_first_application(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21079";
    let svc = "127.0.0.1:21074";
    let dir = ctx.work.join("cold-install");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let app = dir.join(format!("not-preinstalled{}", ctx.exe));
    let mut tower = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .cold_install()
        .readiness_health(svc)
        .check_interval("1s")
        .guardian()?;
    if dir.join("install/state/installed.json").exists()
        || dir.join("install/active-release").exists()
        || app.exists()
    {
        return fail("cold-install fixture accidentally contained a preinstalled application");
    }
    let process = Proc::spawn("cold-install", &mut tower)?;
    let installed = process.wait_for_log(
        "cold-installed application 1.0.0 from the first trusted assignment",
        120,
    ) && wait_for_version(svc, "1.0.0", 120)
        && dir.join("install/state/installed.json").is_file()
        && dir.join("install/active-release").is_file();
    let log = process.captured_log();
    drop(process);
    kill_stray(&dir.join("install"));
    if !installed {
        return fail(format!(
            "bootstrap did not cold-install and launch the first application:\n{log}"
        ));
    }
    ok("bootstrap started with only the update runtime, installed the trusted bundle, and launched it");
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
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let app = dir.join(format!("not-preinstalled{}", ctx.exe));
    let cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .cold_install()
        .check_interval("2s")
        .health_grace("2s")
        .readiness_health(svc)
        .guardian()?;
    let sup = Service::spawn("handoff", &cmd);
    let fail_log = |msg: &str| -> R { fail(format!("{msg}\nlog:\n{}", sup.captured_log())) };

    let install_journal = dir.join("install/state/install.json");
    let update_journal = dir.join("install/state/transaction.json");
    let installed = dir.join("install/state/installed.json");

    // Install machine: cold-install v1, then prove it converged and left NO install journal.
    if !sup.wait_for_log(
        "cold-installed application 1.0.0 from the first trusted assignment",
        EVENT_TIMEOUT,
    ) || !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT)
    {
        return fail_log("install machine did not cold-install and launch v1.0.0");
    }
    if !wait_until(EVENT_TIMEOUT, || !install_journal.exists()) {
        return fail_log("install machine left its journal behind after committing");
    }

    // Update machine: publish v2; the supervisor loop takes over. Prove it converges to v2 and
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
    let log = sup.captured_log();
    drop(sup);
    kill_stray(&dir.join("install"));
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
    let probes = "127.0.0.1:21141";
    let dir = ctx.work.join("app");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("2s")
        .health_grace("2s")
        // This scenario exercises two consecutive update edges. Keep the real
        // confirmation gate, but shorten its window so v3 is not published until the
        // v1 -> v2 edge has been confirmed.
        .confirmation_window("3s")
        .readiness_health(svc)
        .guardian_probes(probes)
        .guardian()?;
    // Under a simulated init system: a crashing update is rolled back by recovery on the
    // next boot (the guardian rolls the crash up and exits), not by an in-process rollback.
    let sup = Service::spawn("tower", &cmd);
    // On any failure, attach the tower's captured log (guardian + supervisor). The install
    // state is already dumped by the runner, so between the two a hang or wrong-state is
    // diagnosable from the failure alone rather than needing a re-run.
    let fail_log = |msg: &str| -> R { fail(format!("{msg}\nlog:\n{}", sup.captured_log())) };

    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail_log("service never came up at v1.0.0");
    }
    // The application socket becomes observable before the supervisor has completed
    // health verification and told the guardian to admit traffic. Probe state is a
    // separate, asynchronous state-machine output, so wait for that output instead of
    // treating application bind as a synchronization barrier.
    if !wait_until(EVENT_TIMEOUT, || {
        ["livez", "readyz", "startupz"]
            .iter()
            .all(|endpoint| http_text(&format!("http://{probes}/{endpoint}")).is_some())
    }) {
        return fail_log("guardian probes did not reach the serving state after startup");
    }
    ok("v1.0.0 live from the TUF repository");

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    // The readiness withdrawal during a stop/start swap is transient: the guardian drops
    // readyz only until the candidate proves healthy, a window that can close in well under
    // one poll interval. Polling the probe endpoint for it therefore races the swap and
    // drops the scenario ~1/10. Assert it from the guardian's durable log instead — the
    // append-only capture cannot miss the transition however briefly it lasts.
    if !sup.wait_for_log(
        "withdrew the application from traffic; the tower stays live",
        EVENT_TIMEOUT,
    ) {
        return fail_log(
            "guardian did not withdraw readiness while remaining live during stop/start",
        );
    }
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail_log("service did not upgrade to v2.0.0");
    }
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{probes}/readyz")).is_some()
    }) {
        return fail_log("guardian did not return to ready after candidate verification");
    }
    ok("unattended upgrade to v2.0.0");

    if !sup.wait_for_log(
        "update 2.0.0 confirmed; confirmation window passed",
        EVENT_TIMEOUT,
    ) {
        return fail_log("v2.0.0 was not confirmed before the next update");
    }

    // A validly signed target that exits immediately (the `server` binary rejects the
    // app's args): a real swap whose candidate fails its health gate during activation.
    // The transaction rejects the crashing release and leaves a durable rollback journal,
    // then the disposable supervisor terminates so *boot recovery* restores v2 on the next
    // launch — the single rollback path. (A supervisor crash mid-transaction lands on the
    // very same recovery, which is what the chaos scenarios cover.)
    ctx.publish(&dir, "app", "3.0.0", &ctx.server.clone())?;
    // 1. The disposable supervisor defers the rollback to boot recovery and exits.
    if !sup.wait_for_log(
        "update failed after activation; restarting so boot recovery rolls back",
        EVENT_TIMEOUT,
    ) {
        return fail_log("the crashing v3.0.0 did not defer its rollback to boot recovery");
    }
    // 2. The relaunched supervisor rejects the bad bytes...
    if !sup.wait_for_log(
        "recovery: rejected 3.0.0 after failed activation",
        EVENT_TIMEOUT,
    ) {
        return fail_log("boot recovery did not reject the crashing v3.0.0");
    }
    // 3. ...and restores the predecessor.
    if !sup.wait_for_log(
        "restoring predecessor 2.0.0 after interrupted activation of 3.0.0",
        EVENT_TIMEOUT,
    ) {
        return fail_log("boot recovery did not roll back to v2.0.0");
    }
    if !wait_for_version(svc, "2.0.0", EVENT_TIMEOUT) {
        return fail_log("service did not recover to v2.0.0 after the crashing v3.0.0");
    }
    ok("broken v3.0.0 applied, crashed before commit, was rejected, and boot recovery restored v2.0.0");
    kill_stray(&app);
    Ok(())
}

/// Zero-downtime for a *stop-start* (full process restart) upgrade. Unlike a same-socket
/// reexec (proven separately by the HAProxy master-worker test), a stop-start drops the
/// listening socket — so zero-downtime here depends entirely on the drain: the built-in drain
/// flips this node's
/// readiness probe to unready *before* the old process is stopped, the guardian keeps it
/// unready until the new release is healthy, and a tiny post-drain provider holds long
/// enough for a readiness-aware load balancer to observe it. We prove that by putting a
/// stand-in load balancer in front: 15 clients that only send to a Ready node must lose
/// zero requests across the whole restart.
pub(crate) fn zero_downtime_stop_start(ctx: &Ctx) -> R {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let (srv, svc, probes) = ("127.0.0.1:21150", "127.0.0.1:21151", "127.0.0.1:21152");
    let dir = ctx.work.join("zd-stop-start");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    // The whole post-drain provider: hold on the post-drain phase so the load balancer
    // observes readyz failing before the old release is stopped.
    let fixture = dir.join("drain-grace-fixture");
    let lifecycle = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "drain-grace".into(),
    ];
    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("1s")
        .health_grace("2s")
        .readiness_health(svc)
        .guardian_probes(probes)
        .lifecycle(lifecycle)
        .guardian()?;
    let _sup = Proc::spawn("supervisor", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        return fail("service never came up at v1.0.0");
    }
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{probes}/readyz")).is_some()
    }) {
        return fail("guardian never admitted traffic (readyz) at v1.0.0");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    let served = Arc::new(AtomicU64::new(0));
    let readyz = format!("http://{probes}/readyz");
    let url = format!("http://{svc}/version");
    let workers: Vec<_> = (0..15)
        .map(|_| {
            let (stop, dropped, served, readyz, url) = (
                stop.clone(),
                dropped.clone(),
                served.clone(),
                readyz.clone(),
                url.clone(),
            );
            std::thread::spawn(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(2))
                    .build();
                let ready = |agent: &ureq::Agent| {
                    agent
                        .get(&readyz)
                        .call()
                        .map(|r| r.status() == 200)
                        .unwrap_or(false)
                };
                while !stop.load(Ordering::Relaxed) {
                    // A load balancer only routes to a Ready node; a draining node being
                    // skipped is correct removal, not a dropped request.
                    if !ready(&agent) {
                        continue;
                    }
                    served.fetch_add(1, Ordering::Relaxed);
                    let ok = agent
                        .get(&url)
                        .call()
                        .ok()
                        .and_then(|response| response.into_string().ok())
                        .is_some_and(|body| body == "1.0.0" || body == "2.0.0");
                    // A failure only counts as a drop if the node still advertised Ready —
                    // otherwise it drained mid-request and a real LB had already stopped it.
                    if !ok && ready(&agent) {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    std::thread::sleep(Duration::from_secs(2));
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let reached = wait_for_version(svc, "2.0.0", EVENT_TIMEOUT);
    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.join();
    }

    if !reached {
        return fail("service did not upgrade to v2.0.0 under load");
    }
    let (d, s) = (
        dropped.load(Ordering::Relaxed),
        served.load(Ordering::Relaxed),
    );
    if d != 0 {
        return fail(format!(
            "stop-start drain dropped {d} of {s} requests sent to a Ready node — not zero-downtime"
        ));
    }
    kill_stray(&app);
    ok(&format!(
        "stop-start upgrade drained cleanly: {s} requests to Ready nodes, 0 dropped across the restart"
    ));
    Ok(())
}

/// Exercise failures in the managed process itself. These are real signed bundles and
/// real localhost HTTP exchanges; no supervisor or guardian dependency is mocked.
pub(crate) fn chaotic_application_health_failures(ctx: &Ctx) -> R {
    let cases = [
        ("exit-before-bind", 22100u16, false),
        ("unhealthy", 22101, false),
        ("hang-health", 22102, false),
        ("flapping", 22105, false),
        ("crash-on-health", 22106, false),
        // This one becomes ready and commits first, then continuous readiness and
        // liveness checks degrade. It must roll up the tower rather than remaining a
        // live-but-unhealthy process forever.
        ("degrade-after-ready", 22107, true),
    ];

    for (fault, port, becomes_ready) in cases {
        let srv = format!("127.0.0.1:{}", port + 100);
        let svc = format!("127.0.0.1:{port}");
        let probes = format!("127.0.0.1:{}", port + 200);
        let dir = ctx.work.join(format!("chaotic-health-{fault}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
        let _server = ctx.serve(&dir, &srv)?;
        let unplaced = dir.join(format!("not-preinstalled{}", ctx.exe));
        let command = Sup::new(
            ctx,
            &dir,
            &srv,
            "app",
            appcmd(&unplaced, &["--addr", &svc, "--fault", fault]),
        )
        .cold_install()
        .check_interval("1s")
        .health_grace("4s")
        .health_successes(if fault == "flapping" { 2 } else { 1 })
        .readiness_health(&svc)
        .guardian_probes(&probes)
        .guardian()?;
        let tower = Service::spawn("chaotic-app", &command);

        if becomes_ready {
            if !wait_for_version(&svc, "1.0.0", EVENT_TIMEOUT)
                || !wait_until(EVENT_TIMEOUT, || {
                    http_text(&format!("http://{probes}/readyz")).is_some()
                })
            {
                return fail(format!(
                    "fault {fault}: application never reached its intentional initial ready state"
                ));
            }
            if !tower.wait_for_log(
                "the managed application failed its liveness check",
                EVENT_TIMEOUT,
            ) {
                return fail(format!(
                    "fault {fault}: sustained liveness failures did not roll up the tower"
                ));
            }
        } else {
            if !wait_until(EVENT_TIMEOUT, || {
                http_text(&format!("http://{probes}/readyz")).is_none()
            }) {
                return fail(format!("fault {fault}: guardian incorrectly became ready"));
            }
            let expected = if matches!(fault, "exit-before-bind" | "crash-on-health") {
                "guardian: application exited"
            } else {
                "managed application failed its initial health check"
            };
            if !tower.wait_for_log(expected, EVENT_TIMEOUT) {
                return fail(format!(
                    "fault {fault}: expected failure {expected:?} was not observed"
                ));
            }
        }
        drop(tower);
        kill_stray(&dir.join("install"));
        ok(&format!(
            "signed chaotic application fault {fault} failed in its expected state"
        ));
    }
    Ok(())
}

/// A stateless node whose *first* (cold) assignment is a broken head must not strand crash-looping
/// it. This is the pod-kill-onto-a-broken-rollout case: an emptyDir node returns cold with no
/// rejection history, cold-installs its unlaunchable assigned head, and — because ordered-install
/// fallback is signed in — rejects it and descends to the newest healthy release below it. Two
/// broken heads are stacked above the good 1.0.0, so recovery must descend past BOTH. Run under
/// the init model so the crash → restart → reject → descend cycle plays out exactly as it would in
/// a container whose state dir survives container restarts (which is where the recovery happens).
pub(crate) fn cold_install_descends_past_broken_head(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21230", "127.0.0.1:21231");
    let probes = "127.0.0.1:21232";
    let dir = ctx.work.join("cold-install-fallback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    // The good release below the broken heads.
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Two unlaunchable heads: bytes that verify and stage but cannot exec (a corrupt entrypoint,
    // exactly like the demo's broken rollout versions). The assigned head is the newest (3.0.0),
    // so recovery must descend past both 3.0.0 and 2.0.0 to reach the healthy 1.0.0.
    let broken = dir.join("broken-app");
    std::fs::write(&broken, b"not-a-runnable-application-entrypoint\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &broken)?;
    ctx.publish(&dir, "app", "3.0.0", &broken)?;
    let _server = ctx.serve(&dir, srv)?;
    let unplaced = dir.join(format!("not-preinstalled{}", ctx.exe));
    let command = Sup::new(ctx, &dir, srv, "app", appcmd(&unplaced, &["--addr", svc]))
        .cold_install()
        .ordered_install_fallback()
        .readiness_health(svc)
        .check_interval("1s")
        .health_grace("2s")
        .guardian_probes(probes)
        .guardian()?;
    let tower = Service::spawn("cold-install-fallback", &command);
    // Recovery is proven when the descended-to 1.0.0 actually serves — the node recovered rather
    // than crash-looping the broken head forever. A working descent takes a few boots (~30s); cap
    // the wait so a failure surfaces its rich per-attempt diagnostics quickly instead of hanging.
    const DESCENT_TIMEOUT: u64 = 90;
    if !wait_for_version(svc, "1.0.0", DESCENT_TIMEOUT) {
        let log = tower.captured_log();
        return fail(format!(
            "cold node stranded on a broken assigned head instead of descending to the healthy \
             1.0.0. Supervisor log (the 'no installable application' lines enumerate every \
             candidate and why each was skipped):\n{log}"
        ));
    }
    // Durability: the committed install record names the descended-to 1.0.0, so a further restart
    // relaunches 1.0.0 and never climbs back onto a rejected broken head.
    let state_path = dir.join("install/state/installed.json");
    let settled = wait_until(DESCENT_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&state_path),
            updated::state::Installed::Present(ref state) if state.release.version == "1.0.0"
        )
    });
    drop(tower);
    kill_stray(&dir.join("install"));
    if !settled {
        return fail(
            "descended app served 1.0.0 but the committed install record never settled on it",
        );
    }
    ok("cold-installed a broken assigned head, rejected it, and ordered fallback descended past two broken heads to the healthy 1.0.0");
    Ok(())
}

/// A cold node whose assigned head is a *malformed* bundle — one that verifies its signed archive
/// hash but cannot be extracted or validated (a corrupt or truncated tar.zst, not merely a bad
/// entrypoint) — must reject it at ingest and descend, exactly like a broken runtime head. Two
/// distinct corruption kinds are stacked above the healthy 1.0.0, so ordered fallback must reject
/// two independent malformed hashes *before anything launches* and land on 1.0.0. This guards the
/// cold-install analogue of the update path's malformed-bundle rejection, which previously did not
/// exist — a cold node re-downloaded a malformed head forever instead of descending past it.
pub(crate) fn cold_install_descends_past_corrupt_bundle(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21530", "127.0.0.1:21531");
    let probes = "127.0.0.1:21532";
    let dir = ctx.work.join("cold-install-corrupt");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    // Malformed-but-signed heads: 2.0.0 truncated, 3.0.0 pure garbage. Each verifies its signed
    // archive hash yet fails to extract, so it is rejected at ingest by content hash — before any
    // process starts — and the descent must step past both.
    // The sample binary is version-agnostic (version is stamped into the bundle by the publisher)
    // and the archive is corrupted anyway, so any built source works; only 1.0.0/2.0.0 are built.
    ctx.publish_corrupt(&dir, "app", "2.0.0", &app_v(ctx, "1.0.0"), "truncate")?;
    ctx.publish_corrupt(&dir, "app", "3.0.0", &app_v(ctx, "1.0.0"), "garbage")?;
    let _server = ctx.serve(&dir, srv)?;
    let unplaced = dir.join(format!("not-preinstalled{}", ctx.exe));
    let command = Sup::new(ctx, &dir, srv, "app", appcmd(&unplaced, &["--addr", svc]))
        .cold_install()
        .ordered_install_fallback()
        .readiness_health(svc)
        .check_interval("1s")
        .health_grace("2s")
        .guardian_probes(probes)
        .guardian()?;
    let tower = Service::spawn("cold-install-corrupt", &command);
    // The malformed heads are rejected at ingest (no launch), so the descent is fast; keep a
    // generous cap so a regression surfaces its diagnostics instead of hanging.
    const DESCENT_TIMEOUT: u64 = 90;
    if !wait_for_version(svc, "1.0.0", DESCENT_TIMEOUT) {
        let log = tower.captured_log();
        return fail(format!(
            "cold node stranded on a malformed assigned bundle instead of rejecting it at ingest \
             and descending to the healthy 1.0.0:\n{log}"
        ));
    }
    let state_path = dir.join("install/state/installed.json");
    let settled = wait_until(DESCENT_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&state_path),
            updated::state::Installed::Present(ref state) if state.release.version == "1.0.0"
        )
    });
    let rejected = std::fs::read_to_string(dir.join("install/state/rejected")).unwrap_or_default();
    let rejected_count = rejected.lines().filter(|l| !l.trim().is_empty()).count();
    drop(tower);
    kill_stray(&dir.join("install"));
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

// ===========================================================================
// A committed update that PASSES its health check and then crashes within its
// confirmation window is reverted to the previous version and the bad release
// rejected — one strike, the failure a finite health window cannot catch.
// ===========================================================================
pub(crate) fn app_post_health_crash_reverts(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21089", "127.0.0.1:21099");
    let dir = ctx.work.join("crashloop");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;

    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("2s")
        .health_grace("2s")
        .readiness_health(svc)
        .guardian()?;
    // The init system restarts the tower when the app crashes; on that boot the supervisor
    // sees the unconfirmed update crashed and reverts it (one strike).
    let sup = Service::spawn("tower", &cmd);

    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        kill_stray(&app);
        return fail("service never came up at v1.0.0");
    }
    ok("v1.0.0 live");

    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    // Trigger the crash only after the durable commit. A timer from process start races
    // lifecycle finalization on loaded CI and can accidentally test interrupted activation.
    if !sup.wait_for_log("upgraded to 2.0.0", EVENT_TIMEOUT)
        || http_text(&format!("http://{svc}/crash")).as_deref() != Some("crashing")
    {
        kill_stray(&app);
        return fail("could not trigger the committed v2.0.0 test crash");
    }
    if !sup.wait_for_log("reverting to 1.0.0", EVENT_TIMEOUT) {
        kill_stray(&app);
        return fail("supervisor did not revert the crashing v2.0.0");
    }
    if !wait_for_version(svc, "1.0.0", EVENT_TIMEOUT) {
        kill_stray(&app);
        return fail("service did not recover to v1.0.0 after the revert");
    }
    let rejected = std::fs::read_to_string(dir.join("install/state/rejected")).unwrap_or_default();
    kill_stray(&app);
    if rejected.trim().is_empty() {
        return fail("the crashing release's hash was not rejected");
    }
    ok("a post-health crash reverted to v1.0.0 and rejected the bad release (one strike)");
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
    let mut services = Vec::new();
    let mut servers = Vec::new();

    for (name, repository_addr, service_addr, fails) in nodes {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let app = dir.join(format!("app{}", ctx.exe));
        std::fs::copy(&v1, &app).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        servers.push(ctx.serve(&dir, repository_addr)?);

        let confirmation_window = if fails { "120s" } else { "8s" };
        let command = Sup::new(
            ctx,
            &dir,
            repository_addr,
            "app",
            appcmd(&app, &["--addr", service_addr]),
        )
        .check_interval("1s")
        .health_grace("2s")
        .confirmation_window(confirmation_window)
        .readiness_health(service_addr)
        .guardian()?;
        services.push((name, dir, app, service_addr, Service::spawn(name, &command)));
    }

    for (_, _, _, address, _) in &services {
        if !wait_for_version(address, "1.0.0", EVENT_TIMEOUT) {
            return fail(format!("node at {address} did not start at 1.0.0"));
        }
    }
    for (_, dir, _, _, _) in &services {
        ctx.publish(dir, "app", "2.0.0", &v2)?;
    }
    if !wait_for_version("127.0.0.1:21130", "2.0.0", EVENT_TIMEOUT) {
        return fail("healthy peer did not commit 2.0.0");
    }
    if !services[1]
        .4
        .wait_for_log("upgraded to 2.0.0", EVENT_TIMEOUT)
        || http_text("http://127.0.0.1:21131/crash").as_deref() != Some("crashing")
    {
        return fail("could not trigger the failing peer's committed v2.0.0 crash");
    }
    if !services[1]
        .4
        .wait_for_log("reverting to 1.0.0", EVENT_TIMEOUT)
        || !wait_for_version("127.0.0.1:21131", "1.0.0", EVENT_TIMEOUT)
    {
        return fail("failing peer did not roll back to 1.0.0");
    }
    if !services[0].4.wait_for_log(
        "update 2.0.0 confirmed; confirmation window passed",
        EVENT_TIMEOUT,
    ) || !wait_for_version("127.0.0.1:21130", "2.0.0", EVENT_TIMEOUT)
    {
        return fail("healthy peer was incorrectly rolled back with its failing peer");
    }
    for (_, _, app, _, _) in &services {
        kill_stray(app);
    }
    drop(servers);
    ok("one node rolled back locally while its group peer remained committed at 2.0.0");
    Ok(())
}

// ===========================================================================
// 2. A tampered pinned root is rejected at load (fail closed).
// ===========================================================================
