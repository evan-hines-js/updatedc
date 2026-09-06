use super::super::*;

// Failure deadlines, not reaction delays. Every helper polls and returns as soon as its
// condition is true. Keep these generous for contended Linux CI while the agent
// itself uses one-second checks and bounded transport retries.
const TRANSACTION_START_TIMEOUT: u64 = 120;
const RECOVERY_TIMEOUT: u64 = 120;
const HEALTH_GRACE: &str = "10s";

/// Crash the agent at every application-update transaction boundary; the external service
/// relaunches it and recovery (driven by the on-disk journal) drives the update to a
/// committed version. The chaos is one-shot, so the relaunched agent recovers
/// rather than crashing again. Each boundary runs in a fully isolated dir + repo so
/// there is no shared state to reset.
pub(crate) fn chaos_recovery(ctx: &Ctx) -> R {
    // Enumerated from the agent binary, not hand-copied — so the scenario tests
    // exactly the crossings the agent defines (see `Ctx::chaos_boundaries`).
    let boundaries = ctx.chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 21200 + index);
        let svc = format!("127.0.0.1:{}", 21300 + index);
        let dir = ctx.work.join(format!("chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let _workload = fixture::workload(&dir);
        let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        ctx.publish(&dir, "app", "2.0.0", &v2)?;
        let server = ctx.serve(&dir, &srv)?;
        let mut cmd = Node::new(ctx, &dir, &srv, "app")
            .workload(&svc)
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .command()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let boot = Service::spawn("chaos", &cmd);

        // Repository refresh/provider staging happens before the transaction begins and
        // may consume a full transport timeout on a saturated parallel CI runner. Do not
        // charge that unrelated preparation time against the crash/recovery deadline.
        if !boot.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
            let log = boot.captured_log();
            drop(boot);
            drop(server);
            return fail(format!(
                "update at {point} never reached the transaction boundary preparation gate; log:\n{log}"
            ));
        }

        // The agent converges the update, crashes once at `point`; the service wrapper
        // must observe that crash and launch a fresh agent. Merely seeing v2 at
        // the service endpoint is insufficient for the later boundaries: the new workload
        // can become healthy just before the old agent dies.
        let crash_seen = boot.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let relaunched = wait_until(RECOVERY_TIMEOUT, || boot.log_count("launched agent") >= 2);

        // Prove durable convergence as well as liveness: installed state names the
        // exact v2 bytes and the transaction journal is gone. This catches recovery
        // that briefly serves v2 but leaves a half-committed transaction on disk.
        let state_path = node_paths(&dir).installed;
        let journal_path = node_paths(&dir).journal;
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
        // This scenario observes the address being released, so the workload is ended here rather
        // than at scope end. Consuming the guard keeps `Drop` the one mechanism.
        _workload.stop();
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

/// Crash the agent at every *first-install* journal boundary. There is no predecessor to
/// fall back to, so recovery is not a rollback: the service wrapper relaunches, the on-disk install
/// journal drives the interrupted install to a committed, live release, and no journal is left
/// behind. This proves cold install has the same crash-safe journaled parity as an update.
/// Each boundary runs in its own isolated dir + repo, cold-installed from only the runtime.
pub(crate) fn install_chaos_recovery(ctx: &Ctx) -> R {
    // Enumerated from the agent binary so the scenario crashes at exactly the crossings the
    // install machine defines (see `Ctx::install_chaos_boundaries`).
    let boundaries = ctx.install_chaos_boundaries()?;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 22800 + index);
        let svc = format!("127.0.0.1:{}", 22850 + index);
        let dir = ctx.work.join(format!("install-chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let _workload = fixture::workload(&dir);
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
        let server = ctx.serve(&dir, &srv)?;
        let mut cmd = Node::new(ctx, &dir, &srv, "app")
            .cold_install()
            .workload(&svc)
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .command()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let boot = Service::spawn("install-chaos", &cmd);

        // The first agent cold-installs and crashes once at `point`; the service wrapper must
        // observe that crash and launch a fresh agent that resumes the install.
        let crash_seen = boot.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let relaunched = wait_until(RECOVERY_TIMEOUT, || boot.log_count("launched agent") >= 2);

        // Durable convergence: the installed record names the exact v1 bytes and the install
        // journal is gone. Since the first agent died mid-install, only recovery could
        // have reached this state.
        let state_path = node_paths(&dir).installed;
        let journal_path = node_paths(&dir).install_journal;
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
        // This scenario observes the address being released, so the workload is ended here rather
        // than at scope end. Consuming the guard keeps `Drop` the one mechanism.
        _workload.stop();
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

/// Commit a candidate whose workload dies inside its confirmation window, then kill the recovering
/// agent at every rollback action/journal boundary. Each case must converge to the predecessor with
/// the candidate rejected and no journal left.
pub(crate) fn rollback_chaos_recovery(ctx: &Ctx) -> R {
    let boundaries = ctx.rollback_chaos_boundaries()?;
    // Whether any boundary's recovery reached the `rollback` operation. Which boundaries do is not
    // this scenario's to dictate — a crash after the predecessor is restored and committed leaves
    // nothing left to compensate — but a sweep in which the operation never ran at all would mean
    // the compensating hook is unreachable, and that is worth failing over.
    let mut compensated = false;
    for (index, point) in boundaries.iter().enumerate() {
        let srv = format!("127.0.0.1:{}", 21400 + index);
        let svc = format!("127.0.0.1:{}", 21500 + index);
        let dir = ctx.work.join(format!("rollback-chaos-{point}"));
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        let _workload = fixture::workload(&dir);
        let (v1, v2) = (app_v(ctx, "1.0.0"), app_v(ctx, "2.0.0"));
        ctx.init_repo(&dir)?;
        ctx.publish(&dir, "app", "1.0.0", &v1)?;
        ctx.publish(&dir, "app", "2.0.0", &v2)?;
        let server = ctx.serve(&dir, &srv)?;
        let fixture_root = fixture::root(&dir);

        let mut cmd = Node::new(ctx, &dir, &srv, "app")
            .check_interval("1s")
            .health_grace(HEALTH_GRACE)
            .hold_unconfirmed()
            // The candidate passes its transaction health gate on its first observation and fails
            // every one after it. A workload that merely died would be restarted by the next boot's
            // own converge — the reconciler owns it — so a running, unhealthy release is what makes
            // a boot gate fail and a rollback happen at all.
            .faulty_upgrade(&svc, "degrade-after-ready")
            .command()?;
        cmd.env(updated::env::CHAOS_POINT, point);
        let node = Service::spawn("rollback-chaos", &cmd);
        let abandon = |node: Service, server: Proc, message: String| -> R {
            let log = node.captured_log();
            drop(node);
            drop(server);
            fail(format!("{message}; log:\n{log}"))
        };

        if !node.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
            return abandon(
                node,
                server,
                format!("rollback case {point} never began its update transaction"),
            );
        }

        // This scenario is specifically about the rollback of a committed, unconfirmed release.
        // Trigger it from that durable state — wait for the commit, then crash the agent so the
        // next boot's health gate is the one that renders the verdict on the degraded release —
        // rather than racing a timer against the transaction's finalization on a contended runner.
        if !node.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT) {
            return abandon(
                node,
                server,
                format!("rollback case {point} never committed its degrading candidate"),
            );
        }
        let Some(agent) = pid_after(&node.captured_log(), "service launched agent") else {
            return abandon(
                node,
                server,
                format!("rollback case {point}: the service never reported an agent PID"),
            );
        };
        kill_pid(agent);

        let crash_seen = node.wait_for_log(
            &format!("CHAOS: exiting at boundary \"{point}\""),
            RECOVERY_TIMEOUT,
        );
        let state_path = node_paths(&dir).installed;
        let journal_path = node_paths(&dir).journal;
        let durable = wait_until(RECOVERY_TIMEOUT, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref state)
                    if state.release.version == "1.0.0" && state.rollback_guard.is_none()
            ) && !journal_path.exists()
        });
        let live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
        let rejected = std::fs::read_to_string(node_paths(&dir).rejected)
            .is_ok_and(|contents| !contents.trim().is_empty());
        let attempts = fixture::attempts(&fixture_root);
        // One transaction, two directions, two identities. The forward direction runs under the
        // transaction's own token; candidate `rollback`, predecessor `converge`, and predecessor
        // health all run under that token's dashless `r` twin, because a
        // reconciler that keys completion on the attempt id must never see the same id twice with
        // different arguments. Anything else means an operation borrowed the wrong identity.
        let forward = attempts
            .first()
            .map(|(_, id)| id.clone())
            .unwrap_or_default();
        let compensating = format!("{forward}r");
        let operation_contract_held = !attempts.is_empty()
            && attempts.iter().all(|(operation, id)| {
                matches!(operation.as_str(), "converge" | "healthcheck" | "rollback")
                    && (*id == forward || *id == compensating)
            })
            && attempts
                .iter()
                .any(|(operation, _)| operation == "converge")
            && attempts
                .iter()
                .all(|(operation, id)| operation != "rollback" || *id == compensating);
        compensated |= attempts
            .iter()
            .any(|(operation, _)| operation == "rollback");
        // Candidate compensation must complete before the predecessor is converged. Both use the
        // compensating identity, but the payload subject differs and the operation order is the
        // durable recovery contract.
        let rollback_index = attempts
            .iter()
            .position(|(operation, id)| operation == "rollback" && *id == compensating);
        let predecessor_converge_index = attempts
            .iter()
            .position(|(operation, id)| operation == "healthcheck" && *id == compensating);
        let compensation_precedes_restore = matches!(
            (rollback_index, predecessor_converge_index),
            (Some(rollback), Some(converge)) if rollback < converge
        );
        let log = node.captured_log();
        drop(node);
        drop(server);
        if !crash_seen
            || !durable
            || !live
            || !rejected
            || !operation_contract_held
            || !compensation_precedes_restore
        {
            return fail(format!(
                "rollback recovery at {point} was incomplete (crash_seen={crash_seen}, \
                 durable={durable}, live={live}, rejected={rejected}, \
                 operation_contract_held={operation_contract_held}, \
                 compensation_precedes_restore={compensation_precedes_restore}); \
                 attempts:\n{attempts:?}\nlog:\n{log}"
            ));
        }
    }
    if !compensated {
        return fail(
            "no rollback boundary's recovery ever invoked the reconciler's rollback operation, so \
             the compensating hook is unreachable",
        );
    }
    ok("every rollback action/journal boundary recovered to the predecessor");
    Ok(())
}

fn provider_failure_case(ctx: &Ctx, phase: &str, index: u16) -> R {
    let srv = format!("127.0.0.1:{}", 21800 + index);
    let svc = format!("127.0.0.1:{}", 21900 + index);
    let dir = ctx.work.join(format!("provider-failure-{phase}"));
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, &srv)?;
    let fixture_root = fixture::root(&dir);
    // Every case here injects a PERSISTENT reconciler failure: the operation fails on every
    // attempt, so containment must hold indefinitely rather than being papered over by a lucky
    // retry. The rollback case additionally fails the recovery itself.
    let mode = if phase == "rollback" {
        format!("workload={svc},fail=converge,fail=rollback")
    } else {
        format!("workload={svc},fail={phase}")
    };
    let command = Node::new(ctx, &dir, &srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .mode(&mode)
        .command()?;
    // The single rollback path is boot recovery, so the node runs under the init model: the
    // failed candidate ends the disposable agent and the service wrapper's relaunch recovers it.
    let node = Service::spawn("provider-failure", &command);
    if !node.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = node.captured_log();
        drop(node);
        drop(server);
        return fail(format!(
            "reconciler {phase} case never began its update transaction; log:\n{log}"
        ));
    }
    let observed = wait_until(RECOVERY_TIMEOUT, || {
        let attempts = fixture::attempts(&fixture_root);
        attempts.iter().any(|(operation, _)| operation == phase)
            && attempts
                .iter()
                .any(|(operation, _)| operation == "rollback")
    });
    // The predecessor must be the version actually answering: a contained failure never leaves the
    // candidate serving.
    let predecessor_live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
    let attempts = fixture::attempts(&fixture_root);
    // A failed rollback is retried from the SAME durable evidence, never restarted as a fresh
    // transaction: however many times recovery replays, everything folds to one transaction —
    // its forward token plus at most that token's own compensating identity.
    let one_recovery_identity = fixture::transactions(&attempts).len() == 1;
    let completed_journal_cleared =
        phase == "rollback" || wait_until(RECOVERY_TIMEOUT, || !node_paths(&dir).journal.is_file());
    let journal_present = node_paths(&dir).journal.is_file();
    drop(node);
    drop(server);

    if !observed || !predecessor_live {
        return fail(format!(
            "reconciler {phase} failure escaped containment (live={predecessor_live}); attempts:\n{attempts:?}"
        ));
    }
    if !one_recovery_identity {
        return fail(format!(
            "reconciler {phase} failure was retried under a new transaction identity:\n{attempts:?}"
        ));
    }
    if phase == "rollback" {
        if !journal_present {
            return fail("failed rollback discarded its durable recovery evidence");
        }
    } else if !completed_journal_cleared {
        return fail(format!(
            "reconciler {phase} failure left a completed recovery journal behind"
        ));
    }
    if !attempts
        .iter()
        .any(|(operation, _)| operation == "rollback")
    {
        return fail(format!(
            "reconciler {phase} failure did not invoke rollback:\n{attempts:?}"
        ));
    }
    Ok(())
}

/// Fuzz the timeout-bounded-*hang* failure mode across every forward reconciler hook. The clean
/// exit-nonzero failure at each operation is covered by [`provider_failure_case`]; this covers the
/// other way a hook goes wrong — it wedges and never returns. Each hook must be killed by the
/// agent's hook timeout and recovered from, leaving a *live* predecessor. A stall (no
/// timeout) would freeze the update or strand the workload mid-switchover — either way 1.0.0
/// never comes back within the bound, so "predecessor live" is the invariant that catches it.
/// (Rollback is excluded: its hooks run with the candidate/predecessor reversed, so the forward
/// hang guard cannot target them.)
pub(crate) fn provider_hook_hangs_are_bounded(ctx: &Ctx) -> R {
    const PHASES: &[&str] = &["converge", "healthcheck"];
    for (index, phase) in PHASES.iter().enumerate() {
        provider_hang_case(ctx, phase, index as u16)?;
    }
    ok("every forward reconciler hook hang was bounded by the hook timeout and recovered with the predecessor live");
    Ok(())
}

fn provider_hang_case(ctx: &Ctx, phase: &str, index: u16) -> R {
    // Keep this range disjoint from `chaotic_application_health_failures` (22100..22107).
    let srv = format!("127.0.0.1:{}", 23300 + index);
    let svc = format!("127.0.0.1:{}", 23350 + index);
    let dir = ctx.work.join(format!("provider-hang-{phase}"));
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, &srv)?;
    let fixture_root = fixture::root(&dir);
    let command = Node::new(ctx, &dir, &srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .mode(&format!("workload={svc},hang={phase}"))
        .command()?;
    let node = Service::spawn("provider-hang", &command);
    if !node.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = node.captured_log();
        drop(node);
        drop(server);
        return fail(format!(
            "reconciler hang {phase} case never began its update transaction; log:\n{log}"
        ));
    }
    // The hook wedges at `phase`; the bounded hook timeout must fire and recovery must restore a
    // live predecessor within the window.
    let attempted = wait_until(RECOVERY_TIMEOUT, || {
        fixture::attempts(&fixture_root)
            .iter()
            .any(|(operation, _)| operation == phase)
    });
    let predecessor_live = wait_for_version(&svc, "1.0.0", RECOVERY_TIMEOUT);
    let log = node.captured_log();
    drop(node);
    drop(server);
    if !attempted {
        return fail(format!(
            "reconciler hang {phase}: the hook was never invoked at that operation:\n{log}"
        ));
    }
    if !predecessor_live {
        return fail(format!(
            "reconciler hang {phase}: the wedged hook was not bounded by the hook timeout — the \
             node never recovered a live predecessor within {RECOVERY_TIMEOUT}s:\n{log}"
        ));
    }
    Ok(())
}

/// The double-execution window, as a first-class scenario: crash the agent after a successful
/// `converge` but before its checkpoint lands, so recovery must drive the same transaction's
/// compensating direction and then converge the machine again. This is the exact case the
/// protocol's execution contract makes the hook author's obligation, so it gets its own named
/// proof rather than riding inside the boundary sweep. Three claims, each of which the refactor
/// can break independently:
///
///  * the two directions of one transaction carry DIFFERENT attempt identities, so a reconciler
///    that marks completion under the attempt id never mistakes predecessor `converge` for the
///    forward one it already ran;
///  * every operation of the compensating direction shares ONE identity, so the hook's per-attempt
///    state is findable across a resume boot;
///  * the migration-shaped release's one-way effect lands exactly once however many invocations it
///    takes — the restore point the interrupted attempt took still holds the pre-migration bytes,
///    which is precisely what a hook that double-executed would have clobbered.
pub(crate) fn converge_replay_converges_exactly_once(ctx: &Ctx) -> R {
    // Disjoint from the hang range (23300..) and the health-failure range (22100..).
    let srv = "127.0.0.1:23400";
    let svc = "127.0.0.1:23450";
    let dir = ctx.work.join("converge-replay");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, srv)?;
    let fixture_root = fixture::root(&dir);
    // A migration-shaped release, so replayed `converge` re-enters a genuinely one-way effect: a
    // hook that double-executes copies already-migrated content over its own restore point, which
    // the backup assertions below catch.
    seed_migration_baseline(&dir)?;
    let mut command = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .mode(&format!("workload={svc},migration-shaped"))
        .command()?;
    // One-shot crash exactly between successful converge and its durable checkpoint.
    command.env(updated::env::CHAOS_POINT, "candidate-converge-finished");
    let node = Service::spawn("converge-replay", &command);
    if !node.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = node.captured_log();
        drop(node);
        drop(server);
        return fail(format!(
            "the replay case never began its update transaction; log:\n{log}"
        ));
    }
    let crash_seen = node.wait_for_log(
        "CHAOS: exiting at boundary \"candidate-converge-finished\"",
        RECOVERY_TIMEOUT,
    );
    let state_path = node_paths(&dir).installed;
    let journal_path = node_paths(&dir).journal;
    let durable = wait_until(RECOVERY_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&state_path),
            updated::state::Installed::Present(ref state)
                if state.release.version == "2.0.0"
        ) && !journal_path.exists()
    });
    let attempts = fixture::attempts(&fixture_root);
    // The attempt the crash interrupted is the first one recorded. Its compensating direction is a
    // distinct, derived identity, and everything the recovery does to undo that attempt runs under
    // it: candidate `rollback`, predecessor `converge`, and the predecessor health gate.
    let interrupted = attempts
        .first()
        .map(|(_, id)| id.clone())
        .unwrap_or_default();
    let compensating = format!("{interrupted}r");
    let compensating_operations: Vec<&str> = attempts
        .iter()
        .filter(|(_, id)| *id == compensating)
        .map(|(operation, _)| operation.as_str())
        .collect();
    let directions_are_distinct = !interrupted.is_empty()
        && !compensating_operations.contains(&"converge")
        && compensating_operations.contains(&"healthcheck")
        && compensating_operations.contains(&"rollback")
        && attempts
            .iter()
            .all(|(operation, id)| operation != "rollback" || *id == compensating);
    // The effect landed, and landed once: the migration is on disk, and the restore point the
    // interrupted attempt took still holds the pre-migration bytes. A hook that re-ran the
    // migrating half would have copied `migrated-2.0.0` over that backup.
    let migration = fixture_root.join("migration-state");
    let read = |path: PathBuf| std::fs::read_to_string(path).unwrap_or_default();
    let backup = migration.join("backups").join(&interrupted);
    let effect_landed_once = read(migration.join("live/content.db")) == "migrated-2.0.0\n"
        && read(migration.join("live/app.war")) == "2.0.0\n"
        && read(backup.join("content.db")) == "baseline-content\n"
        && read(backup.join("app.war")) == "1.0.0\n";
    let log = node.captured_log();
    drop(node);
    drop(server);
    if !crash_seen || !durable || !directions_are_distinct || !effect_landed_once {
        let state = migration.display().to_string();
        return fail(format!(
            "the interrupted converge did not land its effect exactly once (crash_seen={crash_seen}, \
             durable={durable}, directions_are_distinct={directions_are_distinct} (forward \
             {interrupted}, compensating {compensating} ran {compensating_operations:?}), \
             effect_landed_once={effect_landed_once}); migration state under {state}: live \
             content={:?} app={:?}, backup content={:?} app={:?}; attempts:\n{attempts:?}\nlog:\n{log}",
            read(migration.join("live/content.db")),
            read(migration.join("live/app.war")),
            read(backup.join("content.db")),
            read(backup.join("app.war")),
        ));
    }
    ok("an interrupted converge was compensated under its own attempt identity and its one-way effect landed exactly once");
    Ok(())
}

pub(crate) fn provider_converge_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "converge", 0)
}
pub(crate) fn provider_healthcheck_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "healthcheck", 1)
}
pub(crate) fn provider_rollback_failure(ctx: &Ctx) -> R {
    provider_failure_case(ctx, "rollback", 2)
}

/// Seed the baseline a migration-shaped release upgrades from: the live content and application
/// archive its `converge` must back up before migrating.
fn seed_migration_baseline(dir: &Path) -> R<PathBuf> {
    let live = fixture::root(dir).join("migration-state/live");
    std::fs::create_dir_all(&live).map_err(str_err)?;
    std::fs::write(live.join("content.db"), b"baseline-content\n").map_err(str_err)?;
    std::fs::write(live.join("app.war"), b"1.0.0\n").map_err(str_err)?;
    Ok(live)
}

pub(crate) fn migration_shaped_upgrade(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21809";
    let svc = "127.0.0.1:21909";
    let dir = ctx.work.join("migration-shaped-upgrade");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let fixture_root = fixture::root(&dir);
    let live = seed_migration_baseline(&dir)?;
    let node = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .confirmation_window("2s")
        .mode(&format!("workload={svc},migration-shaped"))
        .command()?;
    let process = Proc::spawn("migration-shaped", node)?;
    if !wait_for_version(svc, "1.0.0", TRANSACTION_START_TIMEOUT) {
        return fail("the migration-shaped baseline did not become healthy");
    }
    if !process.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = process.captured_log();
        drop(process);
        return fail(format!(
            "the migration-shaped upgrade never began its transaction; log:\n{log}"
        ));
    }
    // The reconciler owns all domain-specific sequencing inside one converge operation.
    //
    // The workload answers as 2.0.0 from inside `converge`, so waiting on the service alone would read
    // the recorded history before the transaction's healthcheck had run. The committed upgrade is
    // the barrier that means every operation of this transaction is behind us.
    let upgraded = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "2.0.0", 1)
            && fixture_root
                .join("migration-state/migration-finalized")
                .is_file()
    }) && process.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT);
    let state = fixture_root.join("migration-state");
    let attempts = fixture::attempts(&fixture_root);
    let ordered = attempts
        .iter()
        .map(|(operation, _)| operation.as_str())
        .eq(["converge", "healthcheck"]);
    let one_attempt = attempts
        .first()
        .is_some_and(|(_, id)| attempts.iter().all(|(_, candidate)| candidate == id));
    let state_is_migrated = std::fs::read_to_string(live.join("content.db")).map_err(str_err)?
        == "migrated-2.0.0\n"
        && std::fs::read_to_string(live.join("app.war")).map_err(str_err)? == "2.0.0\n";
    let backup_is_exact = attempts.first().is_some_and(|(_, id)| {
        let backup = state.join("backups").join(id);
        std::fs::read_to_string(backup.join("content.db"))
            .is_ok_and(|content| content == "baseline-content\n")
            && std::fs::read_to_string(backup.join("app.war")).is_ok_and(|war| war == "1.0.0\n")
    });
    drop(process);
    if !upgraded || !ordered || !one_attempt || !state_is_migrated || !backup_is_exact {
        return fail(format!(
            "the migration-shaped wrapper violated its lifecycle/state contract in {state:?}:\n{attempts:?}"
        ));
    }
    ok("the migration-shaped reconciler converged its migration, passed healthcheck, and retained an exact rollback backup");
    Ok(())
}

pub(crate) fn sample_to_migration_shaped_and_back(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21811";
    let svc = "127.0.0.1:21911";
    let dir = ctx.work.join("sample-migration-sample");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let fixture_root = fixture::root(&dir);
    seed_migration_baseline(&dir)?;
    let node = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .confirmation_window("2s")
        .mode(&format!("workload={svc},migration-shaped-transition"))
        .command()?;
    let process = Proc::spawn("artifact-transition", node)?;
    let migrated = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "2.0.0", 1)
            && fixture_root
                .join("migration-state/migration-finalized")
                .is_file()
    }) && process.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT);
    if !migrated {
        let log = process.captured_log();
        drop(process);
        return fail(format!(
            "the sample -> migration-shaped transition failed:\n{log}"
        ));
    }

    // Reuse the ordinary sample-app executable fixture. `publish-app` writes
    // the requested 3.0.0 release configuration into the immutable bundle.
    ctx.publish(&dir, "app", "3.0.0", &app_v(ctx, "1.0.0"))?;
    let returned = wait_until(RECOVERY_TIMEOUT, || {
        wait_for_version(svc, "3.0.0", 1)
            && fixture::attempts(&fixture_root)
                .iter()
                .filter(|(operation, _)| operation == "converge")
                .map(|(_, id)| id.clone())
                .collect::<std::collections::HashSet<_>>()
                .len()
                == 2
    }) && process.wait_for_log("upgraded to 3.0.0", RECOVERY_TIMEOUT);
    let attempts = fixture::attempts(&fixture_root);
    let log = process.captured_log();
    let identities = fixture::transactions(&attempts).len();
    drop(process);
    if !returned || identities != 2 {
        return fail(format!(
            "the migration-shaped -> sample transition was not a distinct complete transaction:\n{attempts:?}\nnode log:\n{log}"
        ));
    }
    ok("one install switched sample app -> migration-shaped lifecycle -> sample app");
    Ok(())
}

pub(crate) fn migration_shaped_failed_migration_rolls_back(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21810";
    let svc = "127.0.0.1:21910";
    let dir = ctx.work.join("migration-shaped-rollback");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let _server = ctx.serve(&dir, srv)?;
    let fixture_root = fixture::root(&dir);
    let live = seed_migration_baseline(&dir)?;
    let cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .mode(&format!("workload={svc},migration-shaped-fail-converge"))
        .command()?;
    // A failed converge is recovered by the service wrapper's relaunch into boot recovery — the single
    // rollback path — so this node runs under the init model.
    let node = Service::spawn("migration-rollback", &cmd);
    if !wait_for_version(svc, "1.0.0", TRANSACTION_START_TIMEOUT) {
        return fail("the migration-shaped rollback baseline did not become healthy");
    }
    if !node.wait_for_log("applying update 1.0.0 -> 2.0.0", TRANSACTION_START_TIMEOUT) {
        let log = node.captured_log();
        drop(node);
        return fail(format!(
            "the migration-shaped rollback update never began its transaction; log:\n{log}"
        ));
    }
    let restored = wait_until(RECOVERY_TIMEOUT, || {
        fixture_root
            .join("migration-state/rollback-completed")
            .is_file()
            && std::fs::read_to_string(live.join("content.db"))
                .is_ok_and(|content| content == "baseline-content\n")
            && std::fs::read_to_string(live.join("app.war")).is_ok_and(|war| war == "1.0.0\n")
            && wait_for_version(svc, "1.0.0", 1)
    });
    let attempts = fixture::attempts(&fixture_root);
    let rejected = std::fs::read_to_string(node_paths(&dir).rejected).unwrap_or_default();
    let journal_cleared = wait_until(RECOVERY_TIMEOUT, || !node_paths(&dir).journal.is_file());
    let identities = fixture::transactions(&attempts).len();
    let log = node.captured_log();
    drop(node);
    if !restored || identities != 1 || rejected.trim().is_empty() || !journal_cleared {
        return fail(format!(
            "the failed migration did not restore one transaction cleanly:\n{attempts:?}\nlog:\n{log}"
        ));
    }
    ok("a failed migration restored its archive and content backup, rejected the candidate, and cleared recovery state");
    Ok(())
}

/// A machine reboot in the middle of a rollback, which is a different fault from an agent kill: the
/// hook-managed workload dies with the machine, so the restored predecessor is NOT already running
/// when the next boot's health gate observes it. Completed compensation cannot be undone by a
/// health failure: the bounded gate settles on the exact predecessor and reports it unhealthy,
/// without implicitly running its deployment command or inventing a permanent attention hold.
///
/// The rest of the suite structurally cannot see this: the fixture's workload is designed to
/// survive an agent crash, so every other rollback case finds the predecessor already serving.
pub(crate) fn a_reboot_mid_rollback_bounds_lost_predecessor_health(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:23410";
    let svc = "127.0.0.1:23460";
    let dir = ctx.work.join("rollback-reboot");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    ctx.publish(&dir, "app", "2.0.0", &app_v(ctx, "2.0.0"))?;
    let server = ctx.serve(&dir, srv)?;

    let mut cmd = Node::new(ctx, &dir, srv, "app")
        .check_interval("1s")
        .health_grace(HEALTH_GRACE)
        .hold_unconfirmed()
        .faulty_upgrade(svc, "degrade-after-ready")
        .command()?;
    // Crash after predecessor output evidence is restored, before its bounded health gate.
    cmd.env(updated::env::CHAOS_POINT, "predecessor-converge-finished");
    let node = Service::spawn("rollback-reboot", &cmd);
    let abandon = |node: Service, server: Proc, message: String| -> R {
        let log = node.captured_log();
        drop(node);
        drop(server);
        fail(format!("{message}; log:\n{log}"))
    };

    if !node.wait_for_log("upgraded to 2.0.0", RECOVERY_TIMEOUT) {
        return abandon(
            node,
            server,
            "the reboot case never committed its degrading candidate".into(),
        );
    }
    let Some(agent) = pid_after(&node.captured_log(), "service launched agent") else {
        return abandon(
            node,
            server,
            "the service never reported an agent PID".into(),
        );
    };
    kill_pid(agent);
    if !node.wait_for_log(
        "CHAOS: exiting at boundary \"predecessor-converge-finished\"",
        RECOVERY_TIMEOUT,
    ) {
        return abandon(
            node,
            server,
            "the rollback never reached predecessor converge".into(),
        );
    }
    // The reboot: the workload candidate compensation had just restored dies too. From the next
    // boot's point of view the machine is unconverged, exactly as it would be after a power cycle.
    match fixture::workload_pid(&dir) {
        Some(pid) => kill_pid(pid),
        None => {
            return abandon(
                node,
                server,
                "the reconciler recorded no workload to reboot away".into(),
            )
        }
    }

    let reported_unhealthy = node.wait_for_log(
        "settling on that exact previously confirmed release and reporting it unhealthy",
        RECOVERY_TIMEOUT,
    );
    let paths = node_paths(&dir);
    let settled = wait_until(RECOVERY_TIMEOUT, || {
        matches!(
            updated::state::read_installed(&paths.installed),
            updated::state::Installed::Present(ref state)
                if state.release.version == "1.0.0" && state.rollback_guard.is_none()
        ) && !paths.journal.exists()
    });
    let held = updated::command_adapter::read_attention(&paths.install_root)
        .map_err(str_err)?
        .is_some();
    let attempts = fixture::attempts(&fixture::root(&dir));
    let repeated_deploy = attempts
        .iter()
        .any(|(operation, id)| operation == "converge" && id.ends_with('r'));
    let log = node.captured_log();
    drop(node);
    drop(server);
    if !reported_unhealthy || !settled || held || repeated_deploy {
        return fail(format!("lost recovery health must settle on the predecessor and report it unhealthy (reported_unhealthy={reported_unhealthy}, settled={settled}, held={held}, repeated_deploy={repeated_deploy}):\n{log}"));
    }
    ok("lost predecessor health reached bounded unhealthy settlement without repeating deployment");
    Ok(())
}
