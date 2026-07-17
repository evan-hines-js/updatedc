use super::super::*;
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
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
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
    .reload(vec!["kill".into(), "-HUP".into(), "{pid}".into()])
    .guardian()?;
    let _sup = Proc::spawn("supervisor", &mut cmd)?;
    if !wait_for_version(svc, "1.0.0", 25) {
        return fail("service never came up at v1.0.0");
    }

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
                    if agent.get(&url).call().is_err() {
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
    kill_stray(&app);
    ok(&format!(
        "reexec upgraded live across {t} requests with 0 dropped"
    ));
    Ok(())
}

// ===========================================================================
// 10. Crash at every update boundary; a fresh supervisor recovers each time.
// ===========================================================================
