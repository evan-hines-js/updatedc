use super::super::*;

/// Crash the supervisor at every application-update transaction boundary; the guardian
/// relaunches it and recovery (driven by the on-disk journal) drives the update to a
/// committed version. The chaos is one-shot, so the relaunched supervisor recovers
/// rather than crashing again. Each boundary runs in a fully isolated dir + repo so
/// there is no shared state to reset.
pub(crate) fn chaos_recovery(ctx: &Ctx) -> R {
    // Enumerated from the supervisor binary, not hand-copied — so the scenario tests
    // exactly the crossings the supervisor defines (see `Ctx::chaos_boundaries`).
    let boundaries = ctx.chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 21200 + index);
        let svc = format!("127.0.0.1:{}", 21300 + index);
        let dir = ctx.work.join(format!("chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
        let app = dir.join(format!("app{}", ctx.exe));
        std::fs::copy(&v1, &app).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        ctx.publish(&dir, "app", "2.0.0", &v2)?;
        let server = ctx.serve(&dir, &srv)?;
        let mut cmd = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
            .health(&svc)
            .check_interval("1s")
            .health_grace("2s")
            .guardian()?;
        cmd.env("UPDATED_CHAOS_POINT", point);
        let boot = Proc::spawn("chaos", &mut cmd)?;

        // The supervisor applies the update, crashes once at `point`; the guardian
        // must observe that crash and launch a fresh supervisor. Merely seeing v2 at
        // the health endpoint is insufficient for the later boundaries: the new app
        // can become healthy just before the old supervisor dies.
        let crash_seen = boot.wait_for_log(&format!("CHAOS: exiting at boundary \"{point}\""), 30);
        let relaunched = wait_until(30, || boot.log_count("launched supervisor") >= 2);

        // Prove durable convergence as well as liveness: installed state names the
        // exact v2 bytes and the transaction journal is gone. This catches recovery
        // that briefly serves v2 but leaves a half-committed transaction on disk.
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/transaction.json");
        let durable = wait_until(40, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "2.0.0"
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "2.0.0", 10);
        let log = boot.captured_log();
        drop(boot);
        drop(server);
        kill_stray(&dir.join("install"));
        let stopped = wait_until(10, || http_text(&format!("http://{svc}/version")).is_none());
        if !crash_seen || !relaunched || !durable || !live || !stopped {
            return fail(format!(
                "recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 relaunched={relaunched}, durable={durable}, live={live}, stopped={stopped}); log:\n{log}"
            ));
        }
    }
    ok("every update crash boundary recovered to the committed version");
    Ok(())
}

/// Commit a candidate that deliberately crashes inside its confirmation window, then
/// kill the recovering supervisor at every rollback action/journal boundary. Each case
/// must converge to the predecessor with the candidate rejected and no journal left.
pub(crate) fn rollback_chaos_recovery(ctx: &Ctx) -> R {
    let boundaries = ctx.rollback_chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 21400 + index);
        let svc = format!("127.0.0.1:{}", 21500 + index);
        let dir = ctx.work.join(format!("rollback-chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
        let app = dir.join(format!("app{}", ctx.exe));
        std::fs::copy(&v1, &app).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        ctx.publish(&dir, "app", "2.0.0", &v2)?;
        let server = ctx.serve(&dir, &srv)?;
        let fixture = dir.join("lifecycle-fixture");
        let fixture_command = vec![
            std::env::current_exe()
                .map_err(str_err)?
                .display()
                .to_string(),
            "--lifecycle-fixture".into(),
            fixture.display().to_string(),
        ];

        let mut cmd = Sup::new(
            ctx,
            &dir,
            &srv,
            "app",
            appcmd(
                &app,
                &[
                    "--addr",
                    &svc,
                    "--crash-version",
                    "2.0.0",
                    "--crash-after-ms",
                    "4000",
                ],
            ),
        )
        .health(&svc)
        .check_interval("1s")
        .health_grace("2s")
        .confirmation_window("30s")
        .lifecycle(fixture_command)
        .guardian()?;
        cmd.env("UPDATED_CHAOS_POINT", point);
        let tower = Service::spawn("rollback-chaos", &cmd);

        let crash_seen = tower.wait_for_log(&format!("CHAOS: exiting at boundary \"{point}\""), 45);
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/transaction.json");
        let durable = wait_until(45, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "1.0.0" && state.pending.is_none()
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "1.0.0", 15);
        let rejected = std::fs::read_to_string(dir.join("install/state/rejected"))
            .is_ok_and(|contents| !contents.trim().is_empty());
        let attempts = std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
        let parsed: Vec<(&str, &str)> = attempts
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .collect();
        let ids: std::collections::HashSet<&str> = parsed.iter().map(|(_, id)| *id).collect();
        let count = |phase: &str| parsed.iter().filter(|(p, _)| *p == phase).count();
        let expected_rollback_calls = usize::from(point == "rollback-lifecycle-applied") + 1;
        let expected_activate_calls = usize::from(point == "predecessor-lifecycle-applied") + 2;
        let expected_stop_calls = usize::from(point == "rollback-stop-applied") + 2;
        let expected_start_calls = usize::from(point == "predecessor-start-applied") + 2;
        let expected_verify_calls = usize::from(point == "predecessor-health-applied") + 2;
        let phase_sequence: Vec<&str> = parsed.iter().map(|(phase, _)| *phase).collect();
        let mut expected_sequence = vec![
            "preflight",
            "prepare",
            "drain",
            "stop",
            "activate",
            "start",
            "verify",
            "finalize",
        ];
        expected_sequence.extend(std::iter::repeat_n("stop", expected_stop_calls - 1));
        expected_sequence.extend(std::iter::repeat_n("activate", expected_activate_calls - 1));
        expected_sequence.extend(std::iter::repeat_n("start", expected_start_calls - 1));
        expected_sequence.extend(std::iter::repeat_n("verify", expected_verify_calls - 1));
        expected_sequence.extend(std::iter::repeat_n("rollback", expected_rollback_calls));
        let calls_are_minimal = ["preflight", "prepare", "drain", "finalize"]
            .iter()
            .all(|phase| count(phase) == 1)
            && count("stop") == expected_stop_calls
            && count("activate") == expected_activate_calls
            && count("start") == expected_start_calls
            && count("verify") == expected_verify_calls
            && count("rollback") == expected_rollback_calls
            && phase_sequence == expected_sequence
            && ids.len() == 1;
        let effect_names: Vec<String> = std::fs::read_dir(fixture.join("effects"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        let effects_are_idempotent = [
            "preflight",
            "prepare",
            "drain",
            "stop",
            "activate",
            "start",
            "verify",
            "finalize",
            "rollback",
        ]
        .iter()
        .all(|phase| {
            effect_names
                .iter()
                .filter(|name| name.ends_with(&format!("-{phase}")))
                .count()
                == 1
        });
        let log = tower.captured_log();
        drop(tower);
        drop(server);
        kill_stray(&dir.join("install"));
        if !crash_seen
            || !durable
            || !live
            || !rejected
            || !calls_are_minimal
            || !effects_are_idempotent
        {
            return fail(format!(
                "rollback recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 durable={durable}, live={live}, rejected={rejected}, \
                 calls_are_minimal={calls_are_minimal}, effects_are_idempotent={effects_are_idempotent}); \
                 attempts:\n{attempts}\nlog:\n{log}"
            ));
        }
    }
    ok("every rollback action/journal boundary recovered to the predecessor");
    Ok(())
}

/// A failed drain is a distinct terminal path: rollback has already restored external
/// state, then `aborted` is journaled before cleanup. Crash in that final gap and prove
/// recovery clears evidence without replaying any completed lifecycle phase.
pub(crate) fn aborted_transition_chaos_recovery(ctx: &Ctx) -> R {
    let points = ctx.abort_chaos_boundaries()?;
    if points.as_slice() != ["aborted"] {
        return fail(format!("unexpected abort chaos points: {points:?}"));
    }
    let (srv, svc) = ("127.0.0.1:21600", "127.0.0.1:21700");
    let dir = ctx.work.join("chaos-aborted");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let server = ctx.serve(&dir, srv)?;
    let fixture = dir.join("lifecycle-fixture");
    let fixture_command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "fail-drain".into(),
    ];
    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .health(svc)
        .check_interval("5s")
        .health_grace("2s")
        .lifecycle(fixture_command)
        .guardian()?;
    cmd.env("UPDATED_CHAOS_POINT", "aborted");
    let tower = Proc::spawn("abort-chaos", &mut cmd)?;
    let crash_seen = tower.wait_for_log("CHAOS: exiting at boundary \"aborted\"", 30);
    let durable = wait_until(30, || {
        matches!(
            updated::state::read_installed(&dir.join("install/state/installed.json")),
            updated::state::Installed::Present(ref state)
                if state.release.version == "1.0.0"
        ) && !dir.join("install/state/transaction.json").exists()
    });
    let live = wait_for_version(svc, "1.0.0", 10);
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
    let phases: Vec<&str> = attempts
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(phase, _)| phase))
        .collect();
    let log = tower.captured_log();
    drop(tower);
    drop(server);
    kill_stray(&dir.join("install"));
    if !crash_seen || !durable || !live || phases != ["preflight", "prepare", "drain", "rollback"] {
        return fail(format!(
            "aborted recovery failed (crash_seen={crash_seen}, durable={durable}, live={live}, \
             phases={phases:?}); attempts:\n{attempts}\nlog:\n{log}"
        ));
    }
    ok("aborted drain recovery cleared its journal without replaying completed scripts");
    Ok(())
}

/// Recovery retries one interrupted attempt with the same ID, but after that attempt is
/// durably aborted the next selection must get a fresh ID. This prevents an operator's
/// idempotency cache from suppressing work belonging to a genuinely new attempt.
pub(crate) fn transition_attempt_ids_are_scoped(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:21601", "127.0.0.1:21701");
    let dir = ctx.work.join("lifecycle-attempt-ids");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    ctx.publish(&dir, "app", "2.0.0", &v2)?;
    let server = ctx.serve(&dir, srv)?;
    let fixture = dir.join("lifecycle-fixture");
    let fixture_command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "fail-first-drain".into(),
    ];
    let mut cmd = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .health(svc)
        .check_interval("1s")
        .health_grace("2s")
        .lifecycle(fixture_command)
        .guardian()?;
    let tower = Proc::spawn("attempt-ids", &mut cmd)?;
    // Seeing v2 only proves candidate start/health; finalization runs afterward. Wait for
    // both externally visible service convergence and the complete lifecycle contract so
    // this assertion cannot sample a valid attempt halfway through its final phase.
    let upgraded = wait_until(35, || {
        let serving_v2 = http_text(&format!("http://{svc}/version")).as_deref() == Some("2.0.0");
        let finalized = std::fs::read_to_string(fixture.join("attempts.log"))
            .is_ok_and(|attempts| attempts.lines().any(|line| line.starts_with("finalize\t")));
        serving_v2 && finalized
    });
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
    let parsed: Vec<(&str, &str)> = attempts
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect();
    let first_id = parsed.first().map(|(_, id)| *id).unwrap_or_default();
    let rollback_id = parsed
        .iter()
        .find(|(phase, _)| *phase == "rollback")
        .map(|(_, id)| *id)
        .unwrap_or_default();
    let ids: Vec<&str> = parsed.iter().map(|(_, id)| *id).collect();
    let distinct: std::collections::HashSet<&str> = ids.iter().copied().collect();
    let second_id = ids
        .iter()
        .copied()
        .find(|id| *id != first_id)
        .unwrap_or_default();
    let second_phases: Vec<&str> = parsed
        .iter()
        .filter_map(|(phase, id)| (*id == second_id).then_some(*phase))
        .collect();
    let first_phases: Vec<&str> = parsed
        .iter()
        .filter_map(|(phase, id)| (*id == first_id).then_some(*phase))
        .collect();
    let log = tower.captured_log();
    drop(tower);
    drop(server);
    kill_stray(&dir.join("install"));
    if !upgraded
        || distinct.len() != 2
        || rollback_id != first_id
        || first_phases != ["preflight", "prepare", "drain", "rollback"]
        || second_phases
            != [
                "preflight",
                "prepare",
                "drain",
                "stop",
                "activate",
                "start",
                "verify",
                "finalize",
            ]
    {
        return fail(format!(
            "attempt IDs were not scoped correctly (upgraded={upgraded}, distinct={}, \
             rollback_matches_first={}, first_phases={first_phases:?}, \
             second_phases={second_phases:?}); attempts:\n{attempts}\nlog:\n{log}",
            distinct.len(),
            rollback_id == first_id
        ));
    }
    ok("recovery reused its attempt ID and the post-abort retry received a fresh ID");
    Ok(())
}
