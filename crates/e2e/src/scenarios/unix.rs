use super::super::*;

fn hup_transition() -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        "case \"$UPDATED_TRANSITION_PHASE\" in activate) exec kill -HUP \"$UPDATED_CHILD_PID\" ;; *) exit 0 ;; esac".into(),
    ]
}

fn preflight_rejecting_hup_transition() -> Vec<String> {
    vec![
        "sh".into(),
        "-c".into(),
        "case \"$UPDATED_TRANSITION_PHASE\" in preflight) test \"$UPDATED_CANDIDATE_VERSION\" != 2.0.0 ;; activate) exec kill -HUP \"$UPDATED_CHILD_PID\" ;; *) exit 0 ;; esac".into(),
    ]
}
pub(crate) fn key_perms(ctx: &Ctx) -> R {
    use std::os::unix::fs::PermissionsExt;
    let dir = ctx.work.join("keyperms");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    for role in ["root", "targets", "snapshot", "timestamp"] {
        let mode = std::fs::metadata(ctx.key(&dir, role))
            .map_err(str_err)?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return fail(format!("{role} key perms are {mode:o}, expected 600"));
        }
    }
    ok("TUF role keys are owner-only (0600)");
    Ok(())
}

// ===========================================================================
// 9. (Unix) Zero-downtime reload: an in-place re-exec drops no requests.
// ===========================================================================
pub(crate) fn zero_downtime_reexec(ctx: &Ctx) -> R {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let (srv, svc) = ("127.0.0.1:21083", "127.0.0.1:21093");
    let dir = ctx.work.join("zd");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (reexec_app_v(ctx, "1.0.0"), reexec_app_v(ctx, "2.0.0"));
    let app = dir.join("app");
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;

    let mut cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(
            &app,
            &[
                "--addr",
                svc,
                "--reload-mode",
                "reexec",
                "--reload-signal",
                "HUP",
            ],
        ),
    )
    .check_interval("1s")
    .health_grace("2s")
    .health(svc)
    .reexec(hup_transition())
    .guardian()?;
    let _sup = Proc::spawn("supervisor", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        return fail("service never came up at v1.0.0");
    }
    let initial_pid = http_text(&format!("http://{svc}/pid")).ok_or("missing initial PID")?;

    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let url = format!("http://{svc}/version");
    let workers: Vec<_> = (0..15)
        .map(|_| {
            let (stop, failed, total, url) =
                (stop.clone(), failed.clone(), total.clone(), url.clone());
            std::thread::spawn(move || {
                let agent = ureq::AgentBuilder::new()
                    .timeout(Duration::from_secs(2))
                    .build();
                while !stop.load(Ordering::Relaxed) {
                    total.fetch_add(1, Ordering::Relaxed);
                    let valid = agent
                        .get(&url)
                        .call()
                        .ok()
                        .and_then(|response| response.into_string().ok())
                        .is_some_and(|body| body == "1.0.0" || body == "2.0.0");
                    if !valid {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    std::thread::sleep(Duration::from_secs(2));
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let reached = wait_for_version(svc, "2.0.0", 20);
    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.join();
    }

    if !reached {
        return fail("service did not upgrade to v2.0.0 under load");
    }
    let (f, t) = (
        failed.load(Ordering::Relaxed),
        total.load(Ordering::Relaxed),
    );
    if f != 0 {
        return fail(format!(
            "reexec reload dropped {f} of {t} requests — not zero-downtime"
        ));
    }
    if http_text(&format!("http://{svc}/pid")).as_deref() != Some(initial_pid.as_str()) {
        return fail("successful reexec changed the managed master PID");
    }
    kill_stray(&app);
    ok(&format!(
        "reexec upgraded live across {t} requests with 0 dropped"
    ));
    Ok(())
}

/// Preflight starts the durable attempt but remains before activation: a failure must
/// durably abort and clear its journal, never flip the active pointer or signal the master.
pub(crate) fn reexec_preflight_rejects_without_activation(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21112", "127.0.0.1:21113");
    let dir = ctx.work.join("reexec-preflight");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = reexec_app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app)?;
    let _server = ctx.serve(&dir, srv)?;
    let mut cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(
            &app,
            &[
                "--addr",
                svc,
                "--reload-mode",
                "reexec",
                "--reload-signal",
                "HUP",
            ],
        ),
    )
    .check_interval("1s")
    .health_grace("2s")
    .health(svc)
    .reexec(preflight_rejecting_hup_transition())
    .guardian()?;
    let tower = Proc::spawn("reexec-preflight", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        return fail("preflight fixture never started");
    }
    let pid = http_text(&format!("http://{svc}/pid")).ok_or("missing initial PID")?;

    ctx.publish(&dir, "app", "2.0.0", &app)?;
    let rejected = wait_until(20, || {
        tower.log_contains("rejected 2.0.0 before activation")
            && http_text(&format!("http://{svc}/version")).as_deref() == Some("1.0.0")
    });
    if !rejected {
        return fail("failed preflight did not reject the candidate before activation");
    }
    if dir.join("install/state/transaction.json").exists() {
        return fail("failed preflight left an activation journal");
    }
    if http_text(&format!("http://{svc}/pid")).as_deref() != Some(pid.as_str()) {
        return fail("failed preflight disturbed the managed master PID");
    }

    ctx.publish(&dir, "app", "3.0.0", &app)?;
    if !wait_for_version(svc, "3.0.0", 20) {
        return fail("valid release after a preflight rejection did not activate");
    }
    if http_text(&format!("http://{svc}/pid")).as_deref() != Some(pid.as_str()) {
        return fail("valid reexec after preflight rejection changed the master PID");
    }
    ok("preflight rejected v2 before mutation; v1 kept serving and v3 reexeced in the same PID");
    Ok(())
}

/// An authenticated bundle can still contain an entrypoint the kernel cannot execute.
/// Reexec must return to the old image, let the supervisor reject/roll back the candidate,
/// and remain available for the next valid release without changing the master PID.
pub(crate) fn reexec_rejects_unexecutable_without_downtime(ctx: &Ctx) -> R {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let (srv, svc) = ("127.0.0.1:21110", "127.0.0.1:21111");
    let dir = ctx.work.join("reexec-reject");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = reexec_app_v(ctx, "1.0.0");
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app)?;
    let _server = ctx.serve(&dir, srv)?;
    let mut cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(
            &app,
            &[
                "--addr",
                svc,
                "--reload-mode",
                "reexec",
                "--reload-signal",
                "HUP",
            ],
        ),
    )
    .check_interval("1s")
    .health_grace("2s")
    .health(svc)
    .reexec(hup_transition())
    .guardian()?;
    let _tower = Proc::spawn("reexec-reject", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        return fail("reexec rejection fixture never started");
    }
    let pid = http_text(&format!("http://{svc}/pid")).ok_or("missing initial PID")?;

    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicU64::new(0));
    let total = Arc::new(AtomicU64::new(0));
    let worker = {
        let (stop, failed, total) = (stop.clone(), failed.clone(), total.clone());
        let url = format!("http://{svc}/version");
        std::thread::spawn(move || {
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(1))
                .build();
            while !stop.load(Ordering::Relaxed) {
                total.fetch_add(1, Ordering::Relaxed);
                let valid = agent
                    .get(&url)
                    .call()
                    .ok()
                    .and_then(|response| response.into_string().ok())
                    .is_some_and(|body| body == "1.0.0" || body == "3.0.0");
                if !valid {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };

    let bad = dir.join("not-an-executable");
    std::fs::write(&bad, b"not an executable image\n").map_err(str_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).map_err(str_err)?;
    }
    ctx.publish(&dir, "app", "2.0.0", &bad)?;
    let rejected = wait_until(20, || {
        std::fs::metadata(dir.join("install/state/rejected"))
            .map(|metadata| metadata.len() > 0)
            .unwrap_or(false)
            && http_text(&format!("http://{svc}/version")).as_deref() == Some("1.0.0")
    });
    ctx.publish(&dir, "app", "3.0.0", &app)?;
    let upgraded = wait_for_version(svc, "3.0.0", 20);
    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    let final_pid = http_text(&format!("http://{svc}/pid"));
    if !rejected || !upgraded {
        return fail("unexecutable release was not rejected before the following valid upgrade");
    }
    if failed.load(Ordering::Relaxed) != 0 {
        return fail(format!(
            "unexecutable reexec candidate dropped {} of {} requests",
            failed.load(Ordering::Relaxed),
            total.load(Ordering::Relaxed)
        ));
    }
    if final_pid.as_deref() != Some(pid.as_str()) {
        return fail("reexec rejection or following upgrade changed the master PID");
    }
    ok("unexecutable reexec candidate was rejected with no downtime; next valid release used the same PID");
    Ok(())
}

// ===========================================================================
// 10. Crash at every update boundary; a fresh supervisor recovers each time.
// ===========================================================================
