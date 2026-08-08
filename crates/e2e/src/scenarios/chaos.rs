use super::super::*;

// Failure deadlines, not reaction delays. Every helper polls and returns as soon as its
// condition is true. Keep these generous for contended Linux CI while the supervisor
// itself uses one-second checks and bounded transport retries.
const TRANSACTION_START_TIMEOUT: u64 = 120;
const RECOVERY_TIMEOUT: u64 = 120;
const HEALTH_GRACE: &str = "10s";

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
            .readiness_health(&svc)
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .guardian()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let boot = Proc::spawn("chaos", &mut cmd)?;

        // Repository refresh/provider staging happens before the transaction begins and
        // may consume a full transport timeout on a saturated parallel CI runner. Do not
        // charge that unrelated preparation time against the crash/recovery deadline.
        if !boot.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
            let log = boot.captured_log();
            drop(boot);
            drop(server);
            kill_stray(&dir.join("install"));
            return fail(format!(
                "update at {point} never reached the transaction boundary preparation gate; log:\n{log}"
            ));
        }

        // The supervisor applies the update, crashes once at `point`; the guardian
        // must observe that crash and launch a fresh supervisor. Merely seeing v2 at
        // the health endpoint is insufficient for the later boundaries: the new app
        // can become healthy just before the old supervisor dies.
        let crash_seen = boot.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let relaunched = wait_until(RECOVERY_TIMEOUT, || {
            boot.log_count("launched supervisor") >= 2
        });

        // Prove durable convergence as well as liveness: installed state names the
        // exact v2 bytes and the transaction journal is gone. This catches recovery
        // that briefly serves v2 but leaves a half-committed transaction on disk.
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/transaction.json");
        let durable = wait_until(RECOVERY_TIMEOUT, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "2.0.0"
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "2.0.0", RECOVERY_TIMEOUT);
        let log = boot.captured_log();
        drop(boot);
        drop(server);
        kill_stray(&dir.join("install"));
        let stopped = wait_until(RECOVERY_TIMEOUT, || {
            http_text(&format!("http://{svc}/version")).is_none()
        });
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

/// Crash the supervisor at every *first-install* journal boundary. There is no predecessor to
/// fall back to, so recovery is not a rollback: the guardian relaunches, the on-disk install
/// journal drives the interrupted install to a committed, live release, and no journal is left
/// behind. This proves cold install has the same crash-safe journaled parity as an update.
/// Each boundary runs in its own isolated dir + repo, cold-installed from only the runtime.
pub(crate) fn install_chaos_recovery(ctx: &Ctx) -> R {
    // Enumerated from the supervisor binary so the scenario crashes at exactly the crossings the
    // install machine defines (see `Ctx::install_chaos_boundaries`).
    let boundaries = ctx.install_chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 22800 + index);
        let svc = format!("127.0.0.1:{}", 22850 + index);
        let dir = ctx.work.join(format!("install-chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
        let app = dir.join(format!("not-preinstalled{}", ctx.exe));
        let server = ctx.serve(&dir, &srv)?;
        let mut cmd = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
            .cold_install()
            .readiness_health(&svc)
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .guardian()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let boot = Proc::spawn("install-chaos", &mut cmd)?;

        // The first supervisor cold-installs and crashes once at `point`; the guardian must
        // observe that crash and launch a fresh supervisor that resumes the install.
        let crash_seen = boot.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let relaunched = wait_until(RECOVERY_TIMEOUT, || {
            boot.log_count("launched supervisor") >= 2
        });

        // Durable convergence: the installed record names the exact v1 bytes and the install
        // journal is gone. Since the first supervisor died mid-install, only recovery could
        // have reached this state.
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/install.json");
        let durable = wait_until(RECOVERY_TIMEOUT, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "1.0.0"
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
        let log = boot.captured_log();
        drop(boot);
        drop(server);
        kill_stray(&dir.join("install"));
        let stopped = wait_until(RECOVERY_TIMEOUT, || {
            http_text(&format!("http://{svc}/version")).is_none()
        });
        if !crash_seen || !relaunched || !durable || !live || !stopped {
            return fail(format!(
                "install recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 relaunched={relaunched}, durable={durable}, live={live}, stopped={stopped}); log:\n{log}"
            ));
        }
    }
    ok("every cold-install crash boundary recovered to a committed, live first install");
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

        let mut cmd = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .confirmation_window("120s")
            .lifecycle(fixture_command)
            .guardian()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let tower = Service::spawn("rollback-chaos", &cmd);

        if !tower.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
            let log = tower.captured_log();
            drop(tower);
            drop(server);
            kill_stray(&dir.join("install"));
            return fail(format!(
                "rollback case {point} never began its update transaction; log:\n{log}"
            ));
        }

        // This scenario is specifically about rollback of a committed, unconfirmed
        // release. Trigger its crash from that durable state instead of racing a timer
        // against provider finalization on a contended Linux runner.
        if !tower.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT)
            || !wait_for_crash(&svc, RECOVERY_TIMEOUT)
        {
            let log = tower.captured_log();
            drop(tower);
            drop(server);
            kill_stray(&dir.join("install"));
            return fail(format!(
                "rollback case {point} could not trigger its post-commit crash; log:\n{log}"
            ));
        }

        let crash_seen = tower.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let state_path = dir.join("install/state/installed.json");
        let journal_path = dir.join("install/state/transaction.json");
        let durable = wait_until(RECOVERY_TIMEOUT, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "1.0.0" && state.pending.is_none()
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
        let rejected = std::fs::read_to_string(dir.join("install/state/rejected"))
            .is_ok_and(|contents| !contents.trim().is_empty());
        let attempts = std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
        let parsed: Vec<(&str, &str)> = attempts
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .collect();
        let ids: std::collections::HashSet<&str> = parsed.iter().map(|(_, id)| *id).collect();
        let operation_contract_held = !parsed.is_empty()
            && parsed
                .iter()
                .all(|(operation, _)| matches!(*operation, "apply" | "healthcheck" | "rollback"))
            && parsed.iter().any(|(operation, _)| *operation == "apply")
            && parsed.iter().any(|(operation, _)| *operation == "rollback")
            && ids.len() == 1;
        let effect_names: Vec<String> = std::fs::read_dir(fixture.join("effects"))
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        let effects_are_idempotent = ["apply", "healthcheck", "rollback"].iter().all(|phase| {
            effect_names
                .iter()
                // Markers are `{id}-{phase}`; the id is dashless hex, so the phase is
                // everything after the first `-`. Exactly one marker per phase is the
                // idempotency claim: a replayed phase must not leave a second effect.
                .filter(|name| name.split_once('-').map(|(_, tail)| tail) == Some(*phase))
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
            || !operation_contract_held
            || !effects_are_idempotent
        {
            return fail(format!(
                "rollback recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 durable={durable}, live={live}, rejected={rejected}, \
                 operation_contract_held={operation_contract_held}, effects_are_idempotent={effects_are_idempotent}); \
                 attempts:\n{attempts}\nlog:\n{log}"
            ));
        }
    }
    ok("every rollback action/journal boundary recovered to the predecessor");
    Ok(())
}

fn provider_failure_case(ctx: &Ctx, phase: &str, index: u16) -> R {
    let srv = format!("127.0.0.1:{}", 21800 + index);
    let svc = format!("127.0.0.1:{}", 21900 + index);
    let dir = ctx.work.join(format!("provider-failure-{phase}"));
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, &srv)?;
    let fixture = dir.join("lifecycle-fixture");
    // Every case here injects a PERSISTENT provider failure: the phase fails on every attempt, so
    // containment must hold indefinitely rather than being papered over by a lucky retry.
    let mode = if phase == "rollback" {
        "fail-apply-and-rollback".to_string()
    } else {
        format!("fail-{phase}")
    };
    let fixture_command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        mode,
    ];
    let mut command = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .lifecycle(fixture_command)
        .guardian()?;
    let tower = Proc::spawn("provider-failure", &mut command)?;
    if !tower.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = tower.captured_log();
        drop(tower);
        drop(server);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "provider {phase} case never began its update transaction; log:\n{log}"
        ));
    }
    let observed = wait_until(RECOVERY_TIMEOUT, || {
        std::fs::read_to_string(fixture.join("attempts.log")).is_ok_and(|attempts| {
            let saw_phase = attempts
                .lines()
                .any(|line| line.starts_with(&format!("{phase}\t")));
            let saw_rollback = attempts.lines().any(|line| line.starts_with("rollback\t"));
            saw_phase && saw_rollback
        })
    });
    // The predecessor must be the version actually answering: a contained provider failure never
    // leaves the candidate serving.
    let predecessor_live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
    let held_without_replay = if phase == "rollback" {
        std::thread::sleep(Duration::from_secs(2));
        std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default() == attempts
    } else {
        true
    };
    let completed_journal_cleared = phase == "rollback"
        || wait_until(RECOVERY_TIMEOUT, || {
            !dir.join("install/state/transaction.json").is_file()
        });
    let journal_present = dir.join("install/state/transaction.json").is_file();
    drop(tower);
    drop(server);
    kill_stray(&dir.join("install"));

    if !observed || !predecessor_live {
        return fail(format!(
            "provider {phase} failure escaped containment (live={predecessor_live}); attempts:\n{attempts}"
        ));
    }
    if !held_without_replay {
        return fail(format!(
            "provider {phase} failure caused a recovery replay loop:\n{attempts}"
        ));
    }
    if phase == "rollback" {
        if !journal_present {
            return fail("failed rollback discarded its durable recovery evidence");
        }
    } else if !completed_journal_cleared {
        return fail(format!(
            "provider {phase} failure left a completed recovery journal behind"
        ));
    }
    if !attempts.contains("rollback\t") {
        return fail(format!(
            "provider {phase} failure did not invoke rollback:\n{attempts}"
        ));
    }
    Ok(())
}

/// Fuzz the timeout-bounded-*hang* failure mode across every forward lifecycle hook. The clean
/// exit-nonzero failure at each phase is covered by [`provider_failure_case`]; this covers the
/// other way a hook goes wrong — it wedges and never returns. Each hook must be killed by the
/// supervisor's provider timeout and recovered from, leaving a *live* predecessor. A stall (no
/// timeout) would freeze the update or strand the app stopped mid-switchover — either way 1.0.0
/// never comes back within the bound, so "predecessor live" is the invariant that catches it.
/// (Rollback is excluded: its hooks run with the candidate/predecessor reversed, so the forward
/// hang guard cannot target them.)
pub(crate) fn provider_hook_hangs_are_bounded(ctx: &Ctx) -> R {
    const PHASES: &[&str] = &["apply", "healthcheck"];
    for (index, phase) in PHASES.iter().enumerate() {
        provider_hang_case(ctx, phase, index as u16)?;
    }
    ok("every forward lifecycle hook hang was bounded by the provider timeout and recovered with the predecessor live");
    Ok(())
}

fn provider_hang_case(ctx: &Ctx, phase: &str, index: u16) -> R {
    // Keep this range disjoint from `chaotic_application_health_failures`, whose guardian
    // probes occupy 22300..22307 while the scenarios run concurrently.
    let srv = format!("127.0.0.1:{}", 23300 + index);
    let svc = format!("127.0.0.1:{}", 23350 + index);
    let dir = ctx.work.join(format!("provider-hang-{phase}"));
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, &srv)?;
    let fixture = dir.join("lifecycle-fixture");
    let fixture_command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        format!("hang-{phase}"),
    ];
    let mut command = Sup::new(ctx, &dir, &srv, "app", appcmd(&app, &["--addr", &svc]))
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .lifecycle(fixture_command)
        .guardian()?;
    let tower = Proc::spawn("provider-hang", &mut command)?;
    if !tower.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = tower.captured_log();
        drop(tower);
        drop(server);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "provider hang {phase} case never began its update transaction; log:\n{log}"
        ));
    }
    // The hook wedges at `phase`; the bounded provider timeout must fire and recovery must restore
    // a live predecessor within the window.
    let attempted = wait_until(RECOVERY_TIMEOUT, || {
        std::fs::read_to_string(fixture.join("attempts.log"))
            .is_ok_and(|a| a.lines().any(|l| l.starts_with(&format!("{phase}\t"))))
    });
    let predecessor_live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
    let log = tower.captured_log();
    drop(tower);
    drop(server);
    kill_stray(&dir.join("install"));
    if !attempted {
        return fail(format!(
            "provider hang {phase}: the hook was never invoked at that phase:\n{log}"
        ));
    }
    if !predecessor_live {
        return fail(format!(
            "provider hang {phase}: the wedged hook was not bounded by the provider timeout — the \
             node never recovered a live predecessor within {RECOVERY_TIMEOUT}s:\n{log}"
        ));
    }
    Ok(())
}

pub(crate) fn provider_apply_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "apply", 0)
}
pub(crate) fn provider_healthcheck_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "healthcheck", 1)
}
pub(crate) fn provider_rollback_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "rollback", 2)
}

pub(crate) fn magnolia_shaped_upgrade(ctx: &Ctx) -> R {
    use std::time::Instant;

    let srv = "127.0.0.1:21809";
    let svc = "127.0.0.1:21909";
    let dir = ctx.work.join("magnolia-shaped-upgrade");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let fixture = dir.join("lifecycle-fixture");
    let live = fixture.join("magnolia-state/live");
    std::fs::create_dir_all(&live).map_err(str_err)?;
    std::fs::write(live.join("content.db"), b"baseline-content\n").map_err(str_err)?;
    std::fs::write(live.join("app.war"), b"1.0.0\n").map_err(str_err)?;
    let command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "magnolia-shaped".into(),
    ];
    let mut tower = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .confirmation_window("2s")
        .lifecycle(command)
        .guardian()?;
    let process = Proc::spawn("magnolia-shaped", &mut tower)?;
    if !wait_for_version(svc, "1.0.0", TRANSACTION_START_TIMEOUT) {
        return fail("Magnolia-shaped baseline did not become healthy");
    }
    if !process.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = process.captured_log();
        drop(process);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "Magnolia-shaped upgrade never began its transaction; log:\n{log}"
        ));
    }
    // The provider owns all domain-specific sequencing inside one apply operation.
    let upgrade_started = Instant::now();
    let upgraded = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "2.0.0", 1)
            && std::path::Path::new(&fixture)
                .join("magnolia-state/migration-finalized")
                .is_file()
    });
    // `upgraded` already required `migration-finalized`; re-checking the same single marker under
    // a second name added no coverage. What the state assertions below check — the migrated
    // content, the exact backup, and no leftover drain marker — is the real contract.
    let state = fixture.join("magnolia-state");
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).map_err(str_err)?;
    let parsed = attempts
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect::<Vec<_>>();
    let ordered = parsed
        .iter()
        .map(|(operation, _)| *operation)
        .eq(["apply", "healthcheck"]);
    let one_attempt = parsed
        .first()
        .is_some_and(|(_, id)| parsed.iter().all(|(_, candidate)| candidate == id));
    let state_is_migrated = std::fs::read_to_string(live.join("content.db")).map_err(str_err)?
        == "migrated-2.0.0\n"
        && std::fs::read_to_string(live.join("app.war")).map_err(str_err)? == "2.0.0\n"
        && !live.join("draining").exists();
    let backup_is_exact = parsed.first().is_some_and(|(_, id)| {
        let backup = state.join("backups").join(id);
        std::fs::read_to_string(backup.join("content.db"))
            .is_ok_and(|content| content == "baseline-content\n")
            && std::fs::read_to_string(backup.join("app.war")).is_ok_and(|war| war == "1.0.0\n")
    });
    let elapsed = upgrade_started.elapsed();
    drop(process);
    kill_stray(&dir.join("install"));
    if !upgraded || !ordered || !one_attempt || !state_is_migrated || !backup_is_exact {
        return fail(format!(
            "Magnolia-shaped wrapper violated its lifecycle/state contract in {state:?}:\n{attempts}"
        ));
    }
    if elapsed < Duration::from_millis(250) {
        return fail(format!(
            "Magnolia-shaped lifecycle completed unrealistically quickly ({elapsed:?})"
        ));
    }
    ok("Magnolia-shaped provider applied its migration, passed healthcheck, and retained an exact rollback backup");
    Ok(())
}

pub(crate) fn sample_magnolia_sample_transition(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21811";
    let svc = "127.0.0.1:21911";
    let dir = ctx.work.join("sample-magnolia-sample");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;

    let fixture = dir.join("lifecycle-fixture");
    let live = fixture.join("magnolia-state/live");
    std::fs::create_dir_all(&live).map_err(str_err)?;
    std::fs::write(live.join("content.db"), b"baseline-content\n").map_err(str_err)?;
    std::fs::write(live.join("app.war"), b"1.0.0\n").map_err(str_err)?;
    let command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "magnolia-shaped-transition".into(),
    ];
    let mut tower = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .confirmation_window("2s")
        .lifecycle(command)
        .guardian()?;
    let process = Proc::spawn("artifact-transition", &mut tower)?;
    let magnolia_committed = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "2.0.0", 1)
            && fixture.join("magnolia-state/migration-finalized").is_file()
    }) && process.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT);
    if !magnolia_committed {
        let log = process.captured_log();
        drop(process);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "sample -> Magnolia-shaped transition failed:\n{log}"
        ));
    }

    // Reuse the ordinary sample-app executable fixture. `publish-app` writes
    // the requested 3.0.0 release configuration into the immutable bundle.
    ctx.publish(&dir, "app", "3.0.0", &app_v(ctx, "1.0.0"))?;
    let attempts_path = fixture.join("attempts.log");
    let returned = wait_until(RECOVERY_TIMEOUT, || {
        if !wait_for_version(svc, "3.0.0", 1) {
            return false;
        }
        let Ok(attempts) = std::fs::read_to_string(&attempts_path) else {
            return false;
        };
        attempts
            .lines()
            .filter_map(|line| {
                let (phase, id) = line.split_once('\t')?;
                (phase == "apply").then_some(id)
            })
            .collect::<std::collections::HashSet<_>>()
            .len()
            == 2
    }) && process.wait_for_log("upgraded to 3.0.0", RECOVERY_TIMEOUT);
    let attempts = std::fs::read_to_string(&attempts_path).map_err(str_err)?;
    let transaction_ids = attempts
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, id)| id))
        .collect::<std::collections::HashSet<_>>();
    let log = process.captured_log();
    drop(process);
    kill_stray(&dir.join("install"));
    if !returned || transaction_ids.len() != 2 {
        return fail(format!(
            "Magnolia-shaped -> sample transition was not a distinct complete transaction:\n{attempts}\ntower log:\n{log}"
        ));
    }
    ok("one install switched sample app -> Magnolia-shaped lifecycle -> sample app");
    Ok(())
}

pub(crate) fn magnolia_shaped_failed_migration_rolls_back(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21810";
    let svc = "127.0.0.1:21910";
    let dir = ctx.work.join("magnolia-shaped-rollback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let fixture = dir.join("lifecycle-fixture");
    let live = fixture.join("magnolia-state/live");
    std::fs::create_dir_all(&live).map_err(str_err)?;
    std::fs::write(live.join("content.db"), b"baseline-content\n").map_err(str_err)?;
    std::fs::write(live.join("app.war"), b"1.0.0\n").map_err(str_err)?;
    let command = vec![
        std::env::current_exe()
            .map_err(str_err)?
            .display()
            .to_string(),
        "--lifecycle-fixture".into(),
        fixture.display().to_string(),
        "magnolia-shaped-fail-apply".into(),
    ];
    let mut tower = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .lifecycle(command)
        .guardian()?;
    let process = Proc::spawn("magnolia-rollback", &mut tower)?;
    if !wait_for_version(svc, "1.0.0", TRANSACTION_START_TIMEOUT) {
        return fail("Magnolia rollback baseline did not become healthy");
    }
    if !process.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = process.captured_log();
        drop(process);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "Magnolia rollback update never began its transaction; log:\n{log}"
        ));
    }
    let restored = wait_until(RECOVERY_TIMEOUT, || {
        fixture.join("magnolia-state/rollback-completed").is_file()
            && std::fs::read_to_string(live.join("content.db"))
                .is_ok_and(|content| content == "baseline-content\n")
            && std::fs::read_to_string(live.join("app.war")).is_ok_and(|war| war == "1.0.0\n")
            && wait_for_version(svc, "1.0.0", 1)
    });
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).map_err(str_err)?;
    let ids = attempts
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, id)| id))
        .collect::<std::collections::HashSet<_>>();
    let rejected = std::fs::read_to_string(dir.join("install/state/rejected")).unwrap_or_default();
    let journal_cleared = wait_until(RECOVERY_TIMEOUT, || {
        !dir.join("install/state/transaction.json").is_file()
    });
    drop(process);
    kill_stray(&dir.join("install"));
    if !restored || ids.len() != 1 || rejected.trim().is_empty() || !journal_cleared {
        return fail(format!(
            "failed Magnolia migration did not restore one transaction cleanly:\n{attempts}"
        ));
    }
    ok("failed Magnolia migration restored the WAR and content backup, rejected the candidate, and cleared recovery state");
    Ok(())
}
