use super::super::*;

// Failure deadlines, not reaction delays. Every helper polls and returns as soon as its
// condition is true. Keep these generous for contended Linux CI while the supervisor
// itself uses one-second checks and bounded transport retries.
const TRANSACTION_START_TIMEOUT: u64 = 30;
const RECOVERY_TIMEOUT: u64 = 45;

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
            .health(&svc)
            .check_interval("1s")
            .health_grace("2s")
            .confirmation_window("120s")
            .lifecycle(fixture_command)
            .guardian()?;
        cmd.env("UPDATED_CHAOS_POINT", point);
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
            || http_text(&format!("http://{svc}/crash")).as_deref() != Some("crashing")
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
    if !tower.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = tower.captured_log();
        drop(tower);
        drop(server);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "aborted-transition update never began its transaction; log:\n{log}"
        ));
    }
    let crash_seen = tower.wait_for_log("CHAOS: exiting at boundary \"aborted\"", RECOVERY_TIMEOUT);
    let durable = wait_until(RECOVERY_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&dir.join("install/state/installed.json")),
            updated::state::Installed::Present(ref state)
                if state.release.version == "1.0.0"
        ) && !dir.join("install/state/transaction.json").exists()
    });
    let live = wait_for_version(svc, "1.0.0", RECOVERY_TIMEOUT);
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
    if !tower.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = tower.captured_log();
        drop(tower);
        drop(server);
        kill_stray(&dir.join("install"));
        return fail(format!(
            "attempt-ID update never began its first transaction; log:\n{log}"
        ));
    }
    // Seeing v2 only proves candidate start/health; finalization runs afterward. Wait for
    // both externally visible service convergence and the complete lifecycle contract so
    // this assertion cannot sample a valid attempt halfway through its final phase.
    let upgraded = wait_until(RECOVERY_TIMEOUT, || {
        let serving_v2 = http_text(&format!("http://{svc}/version")).as_deref() == Some("2.0.0");
        let two_attempts_finalized = std::fs::read_to_string(fixture.join("attempts.log"))
            .is_ok_and(|attempts| {
                let parsed = attempts
                    .lines()
                    .filter_map(|line| line.split_once('\t'))
                    .collect::<Vec<_>>();
                let distinct = parsed
                    .iter()
                    .map(|(_, id)| *id)
                    .collect::<std::collections::HashSet<_>>();
                distinct.len() == 2 && parsed.iter().any(|(phase, _)| *phase == "finalize")
            });
        serving_v2 && two_attempts_finalized
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
    let retryable = matches!(phase, "prepare" | "drain");
    let mode = if phase == "rollback" {
        "fail-start-and-rollback".to_string()
    } else if retryable {
        format!("fail-first-{phase}")
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
        .health(&svc)
        .check_interval("1s")
        .health_grace("2s")
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
    // A retryable one-shot failure can already have advanced to v2 by the time the
    // attempts file is observed. Its completed rollback is the containment proof.
    let predecessor_live = retryable || wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
    // Only a failed rollback is unrecoverable in-process and must remain held with its
    // journal. All other failures either reject the candidate or defer it after completing
    // rollback. Prepare/drain fail once, then must complete under a fresh transaction ID.
    let fresh_retry = !retryable
        || wait_until(RECOVERY_TIMEOUT, || {
            let attempts =
                std::fs::read_to_string(fixture.join("attempts.log")).unwrap_or_default();
            attempts
                .lines()
                .filter_map(|line| line.split_once('\t'))
                .filter(|(logged_phase, _)| *logged_phase == phase)
                .map(|(_, id)| id)
                .collect::<std::collections::HashSet<_>>()
                .len()
                >= 2
        }) && wait_for_version(&svc, "2.0.0", RECOVERY_TIMEOUT);
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
    if !fresh_retry {
        return fail(format!(
            "provider {phase} deferral did not retry under a fresh transaction ID:\n{attempts}"
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

pub(crate) fn provider_preflight_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "preflight", 0)
}
pub(crate) fn provider_prepare_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "prepare", 1)
}
pub(crate) fn provider_drain_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "drain", 2)
}
pub(crate) fn provider_stop_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "stop", 3)
}
pub(crate) fn provider_activate_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "activate", 4)
}
pub(crate) fn provider_start_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "start", 5)
}
pub(crate) fn provider_verify_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "verify", 6)
}
pub(crate) fn provider_finalize_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "finalize", 7)
}
pub(crate) fn provider_rollback_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "rollback", 8)
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
        .health(svc)
        .check_interval("1s")
        .health_grace("2s")
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
    // Real Java CMS upgrades are deliberately slow: backup, quiesce, stop,
    // deployment, startup, and migration each get their own seconds-scale
    // budget in the fixture. Keep an assertion here so this scenario cannot
    // accidentally regress into a fast mock that hides timeout/race bugs.
    let upgrade_started = Instant::now();
    let upgraded = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "2.0.0", 1)
            && std::path::Path::new(&fixture)
                .join("magnolia-state/migration-finalized")
                .is_file()
    });
    let state = fixture.join("magnolia-state");
    let expected = [
        "preflight-checked",
        "backup-created",
        "authors-drained",
        "tomcat-stopped",
        "war-activated",
        "tomcat-started",
        "cms-health-verified",
        "migration-finalized",
    ];
    let complete = expected.iter().all(|name| state.join(name).is_file());
    let attempts = std::fs::read_to_string(fixture.join("attempts.log")).map_err(str_err)?;
    let parsed = attempts
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect::<Vec<_>>();
    let ordered = parsed.len() == expected.len()
        && parsed.iter().map(|(phase, _)| *phase).eq([
            "preflight",
            "prepare",
            "drain",
            "stop",
            "activate",
            "start",
            "verify",
            "finalize",
        ]);
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
    if !upgraded || !complete || !ordered || !one_attempt || !state_is_migrated || !backup_is_exact
    {
        return fail(format!(
            "Magnolia-shaped wrapper violated its lifecycle/state contract in {state:?}:\n{attempts}"
        ));
    }
    if elapsed < Duration::from_millis(1_500) {
        return fail(format!(
            "Magnolia-shaped lifecycle completed unrealistically quickly ({elapsed:?})"
        ));
    }
    ok("Magnolia-shaped wrapper performed backup, drain, WAR activation, restart, health verification, and finalization");
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
        "magnolia-shaped-fail-finalize".into(),
    ];
    let mut tower = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .health(svc)
        .check_interval("1s")
        .health_grace("10s")
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
