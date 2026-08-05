//! End-to-end test / demo. One cross-platform Rust binary — instead of parallel
//! bash and PowerShell scripts that inevitably drift — that builds the release
//! binaries, stands up a real TUF repository via the `server`, and drives real
//! application-update, rollback, supervisor self-update, crash-recovery, and
//! TUF/hardening scenarios against them. Platform-specific behaviour lives behind
//! `#[cfg(...)]`, not in a second script.
//!
//! Run: `cargo run -p e2e`. Exit 0 means every scenario passed. Scenarios are
//! independent (unique dirs + ports) and run on a bounded thread pool; set
//! `E2E_JOBS=1` to run them one at a time in order.

mod scenarios;

pub use e2e::fixtures::*;
pub use e2e::harness::*;
use scenarios::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
/// The reconciler protocol vocabulary, shared with the supervisor that invokes it, so a scenario
/// cannot be written against an operation name the product no longer speaks.
use updated_contracts::reconciler::Operation;

fn main() {
    if std::env::args().any(|arg| arg == "--lifecycle-fixture") {
        if let Err(error) = run_lifecycle_fixture() {
            eprintln!("lifecycle fixture: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = run_suite() {
        eprintln!("\x1b[1;31mFAIL: {e}\x1b[0m");
        std::process::exit(1);
    }
    println!("\n\x1b[1;32mSUCCESS: all scenarios passed\x1b[0m");
}

/// Cross-platform node reconciler fixture: the one reconciler every scenario runs. It speaks the
/// published protocol vocabulary ([`Operation`]), so an operation this workspace no longer invokes
/// — or a scenario written against a retired spelling — fails loudly here instead of silently
/// answering nothing.
///
/// Every invocation is recorded at one chokepoint before any mode-specific behaviour, so no mode
/// can answer an operation without that operation appearing in the recorded history.
fn run_lifecycle_fixture() -> R {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let operation: Operation = args
        .first()
        .ok_or("missing reconciler operation")?
        .parse()
        .map_err(|error: updated_contracts::reconciler::UnknownOperation| error.to_string())?;
    let phase = operation.as_str();
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing reconciler/provider argument separator")?;
    let value = |name: &str| -> Result<String, String> {
        let index = args[..separator]
            .iter()
            .position(|arg| arg == name)
            .ok_or_else(|| format!("missing {name}"))?;
        args.get(index + 1)
            .cloned()
            .ok_or_else(|| format!("missing value for {name}"))
    };
    if value("--protocol")? != "1" {
        return fail("unsupported reconciler protocol");
    }
    let id = value("--attempt-id")?;
    let candidate_version = value("--candidate-version")?;
    let provider_args = &args[separator + 1..];
    let fixture = provider_args
        .iter()
        .position(|arg| arg == "--lifecycle-fixture")
        .ok_or("missing --lifecycle-fixture")?;
    let root = provider_args
        .get(fixture + 1)
        .map(PathBuf::from)
        .ok_or("missing fixture state directory")?;
    let mode = provider_args.get(fixture + 2).cloned().unwrap_or_default();

    // The one recording chokepoint, ahead of every mode: nothing below may answer an operation
    // that this did not observe.
    record_invocation(&root, operation, &id)?;

    // Inspect is a steady-state observation, not a deployment transaction. The fixture emits
    // deterministic, non-empty state without touching modeled side effects.
    if operation == Operation::Inspect {
        println!("candidate-version={candidate_version}");
        return Ok(());
    }

    let magnolia_mode = mode.starts_with("magnolia-shaped");
    // The same signed provider now belongs to the installed release from the beginning; there is
    // no provider-less seed path. Magnolia's transactional checks apply only once the
    // Magnolia-shaped candidate is active. The ordinary 1.0.0 predecessor therefore has no
    // Magnolia state to inspect, while checks after the 2.0.0 apply require the migration receipt
    // that apply produced.
    if magnolia_mode && operation == Operation::Healthcheck {
        if candidate_version == "1.0.0" || root.join("magnolia-state/migration-finalized").is_file()
        {
            return Ok(());
        }
        return fail("Magnolia healthcheck ran before migration finalized");
    }
    let fail_once_phase = mode.strip_prefix("fail-first-");
    let fail_once = fail_once_phase == Some(phase)
        && std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{phase}-failure-injected")))
            .is_ok();
    if fail_once {
        return fail(format!("injected one-shot {phase} failure"));
    }
    let fail_phase = mode.strip_prefix("fail-");
    let fail_start_and_rollback = mode == "fail-apply-and-rollback"
        && (phase == "rollback" || (phase == "apply" && candidate_version == "2.0.0"));
    // Ordinary failure modes target the forward candidate only. Rollback reverses the
    // candidate/predecessor variables, and must be allowed to start and verify the restored
    // predecessor. The dedicated rollback mode is the exception used to prove that failed
    // recovery remains durably held.
    let fail_forward_candidate = candidate_version == "2.0.0" && fail_phase == Some(phase);
    if fail_forward_candidate || fail_start_and_rollback {
        return fail(format!("injected {phase} failure"));
    }
    // A hook that *hangs* (rather than cleanly exiting non-zero) must be bounded by the
    // supervisor's provider timeout and treated as a failure — not left to stall the update
    // indefinitely. Hang only the forward candidate's target phase, well past the 5s provider
    // timeout, so the supervisor kills us; the rollback (which reverses candidate/predecessor,
    // so this guard no longer matches) then runs normally.
    if mode.strip_prefix("hang-") == Some(phase) && candidate_version == "2.0.0" {
        std::thread::sleep(Duration::from_secs(30));
    }
    if let Some(url) = mode.strip_prefix("http-health=") {
        if phase == "healthcheck" && http_text(url).is_none() {
            return fail(format!("{phase} could not verify {url}"));
        }
        return Ok(());
    }
    if mode == "accept-managed" {
        // The guardian guarantees the child is alive whenever this provider is invoked. This
        // fixture deliberately has no additional application policy.
        return Ok(());
    }
    // Draining is entirely agent-owned now; the provider has no drain operation.
    if mode == "drain-grace" {
        return Ok(());
    }
    // The mixed-artifact scenario uses the Magnolia adapter only while the
    // Magnolia-shaped release is the candidate. Its following ordinary binary
    // deliberately returns to the provider's generic lifecycle path.
    let magnolia_candidate = mode == "magnolia-shaped-transition" && candidate_version == "2.0.0";
    if (mode.starts_with("magnolia-shaped") && mode != "magnolia-shaped-transition")
        || magnolia_candidate
    {
        // A stateful stand-in for a Java/WAR CMS adapter. Each phase verifies the durable
        // prerequisite produced by the preceding phase, so running phases out of order is
        // a hard failure rather than another marker in a directory.
        let state = root.join("magnolia-state");
        let live = state.join("live");
        let backup = state.join("backups").join(&id);
        std::fs::create_dir_all(&state).map_err(str_err)?;
        // Real CMS/WAR upgrades spend meaningful time in backup, quiescence, startup,
        // and migration. Keep CI deterministic while making timeout and ordering behavior
        // observable instead of accidentally testing a zero-latency wrapper.
        std::thread::sleep(std::time::Duration::from_millis(250));
        if phase == "apply" {
            if candidate_version == "1.0.0" {
                return Ok(());
            }
            if std::fs::read_to_string(live.join("content.db")).map_err(str_err)?
                != "baseline-content\n"
                || std::fs::read_to_string(live.join("app.war")).map_err(str_err)? != "1.0.0\n"
            {
                return fail("Magnolia apply found an invalid baseline");
            }
            std::fs::create_dir_all(&backup).map_err(str_err)?;
            std::fs::copy(live.join("content.db"), backup.join("content.db")).map_err(str_err)?;
            std::fs::copy(live.join("app.war"), backup.join("app.war")).map_err(str_err)?;
            std::fs::write(live.join("app.war"), format!("{candidate_version}\n"))
                .map_err(str_err)?;
            std::fs::write(
                live.join("content.db"),
                format!("migrated-{candidate_version}\n"),
            )
            .map_err(str_err)?;
            if mode == "magnolia-shaped-fail-apply" && candidate_version == "2.0.0" {
                return fail("injected Magnolia apply failure");
            }
            std::fs::write(state.join("migration-finalized"), id.as_bytes()).map_err(str_err)?;
            return Ok(());
        }
        if phase == "rollback" {
            std::fs::copy(backup.join("content.db"), live.join("content.db")).map_err(str_err)?;
            std::fs::copy(backup.join("app.war"), live.join("app.war")).map_err(str_err)?;
            let _ = std::fs::remove_file(live.join("draining"));
            std::fs::write(state.join("rollback-completed"), id.as_bytes()).map_err(str_err)?;
            return Ok(());
        }
        return fail(format!("unknown Magnolia lifecycle operation {phase}"));
    }
    Ok(())
}

/// Record one reconciler invocation. This is the fixture's only writer of observation history, so
/// a mode cannot answer an operation the history does not show.
///
/// `operations.log` holds *every* invocation, including the reserved observation identities, and
/// is what a scenario reads to prove the supervisor invoked an operation at all — the readiness
/// gate above all. `attempts.log` and the create-new effect markers hold only deployment
/// operations: they model the transaction history and an idempotent side effect that may happen
/// at most once per (attempt, operation) even when crash recovery replays the command, and the
/// reserved boot/periodic/fingerprint observations must not pollute either.
fn record_invocation(root: &Path, operation: Operation, id: &str) -> R {
    use std::io::Write;

    let append = |path: PathBuf, line: &str| -> R {
        std::fs::create_dir_all(root).map_err(str_err)?;
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(str_err)?;
        writeln!(log, "{line}").map_err(str_err)
    };
    append(
        root.join("operations.log"),
        &format!("{}\t{id}", operation.as_str()),
    )?;
    if updated_contracts::reconciler::attempt::is_reserved(id) {
        return Ok(());
    }
    append(
        root.join("attempts.log"),
        &format!("{}\t{id}", operation.as_str()),
    )?;
    std::fs::create_dir_all(root.join("effects")).map_err(str_err)?;
    let marker = root
        .join("effects")
        .join(format!("{id}-{}", operation.as_str()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
    {
        Ok(mut file) => writeln!(file, "{id}").map_err(str_err),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(str_err(error)),
    }
}

/// A named scenario. To add one: write an `fn(&Ctx) -> R` that asserts its own
/// behaviour (returning `Err` on failure), then add a line to `scenarios()`.
type Scenario = (&'static str, fn(&Ctx) -> R);

fn scenarios() -> Vec<Scenario> {
    let mut s: Vec<Scenario> = vec![
        (
            "application upgrade v1->v2, then rollback of a broken v3",
            app_update_and_rollback,
        ),
        (
            "a stop-start upgrade drains to zero downtime behind a readiness-aware load balancer",
            zero_downtime_stop_start,
        ),
        (
            "bootstrap cold-installs the first application from only the update runtime",
            bootstrap_cold_installs_first_application,
        ),
        (
            "the install machine hands off cleanly to the update machine (no journal overlap)",
            cold_install_hands_off_to_update,
        ),
        (
            "a committed update that crashes after health is reverted + rejected (one strike)",
            app_post_health_crash_reverts,
        ),
        (
            "signed chaotic applications fail closed across distinct health failure modes",
            chaotic_application_health_failures,
        ),
        (
            "a stateless cold node descends past a broken assigned head to the newest healthy release",
            cold_install_descends_past_broken_head,
        ),
        (
            "a cold node rejects a malformed (unextractable) assigned bundle at ingest and descends to a healthy release",
            cold_install_descends_past_corrupt_bundle,
        ),
        (
            "two nodes receive one group release; only the failing node rolls back",
            group_peer_failure_is_node_local,
        ),
        (
            "assigned secrets are injected, rotated by restart, removed, and never persisted",
            assigned_secret_lifecycle,
        ),
        (
            "an incomplete secret bundle fails closed before application launch",
            missing_assigned_secret_blocks_launch,
        ),
        (
            "a tampered enrollment trust root fails closed before application launch",
            tampered_root_fails_closed,
        ),
        (
            "a signed local deployment repairs a modified bundle with no network",
            signed_local_repair_without_network,
        ),
        (
            "a second supervisor on the same install is refused",
            single_instance_lock,
        ),
        (
            "a health-check-failed release stays rejected across a restart",
            persisted_rejection,
        ),
        ("custom provider apply failure rolls back", provider_apply_failure),
        ("custom provider healthcheck failure rolls back", provider_healthcheck_failure),
        ("custom provider rollback failure remains recoverable", provider_rollback_failure),
        ("a wedged provider operation is bounded by its timeout", provider_hook_hangs_are_bounded),
            ("a Magnolia-shaped Java upgrade wrapper completes every lifecycle step", magnolia_shaped_upgrade),
            ("an install switches sample app -> Magnolia-shaped -> sample app", sample_magnolia_sample_transition),
            ("a failed Magnolia migration restores its WAR and content backup", magnolia_shaped_failed_migration_rolls_back),
        (
            "a supervisor crash does not disturb the app; the guardian relaunches it",
            supervisor_crash_preserves_app,
        ),
        (
            "a clean stop (SIGTERM to the guardian) reaps the whole tower — no orphans",
            clean_stop_reaps_the_whole_tower,
        ),
        (
            "the supervisor self-updates by pointer flip; the app never restarts",
            supervisor_self_update,
        ),
        (
            "an unlaunchable supervisor candidate is rolled back, rejected, and never retried",
            supervisor_self_update_rollback,
        ),
        (
            "a ready supervisor that crashes during confirmation is rolled back without disturbing the app",
            supervisor_post_ready_crash_rolls_back,
        ),
    ];
    // Unix-only mechanisms (file modes; fork/exec/signals for zero-downtime).
    #[cfg(unix)]
    {
        s.push(("the TUF role keys are owner-only (0600)", key_perms));
        s.push((
            "lifecycle healthcheck gates first install and upgrade",
            lifecycle_healthcheck_gates_readiness,
        ));
        s.push((
            "a stateless cold node descends past wedged (alive-but-unhealthy) assigned heads to the newest healthy release",
            cold_install_descends_past_wedged_head,
        ));
    }
    // Chaos recovery runs last: it replays every transaction boundary, so it is by
    // far the slowest scenario.
    s.push((
        "crash at every cold-install boundary; recovery completes the first install",
        install_chaos_recovery,
    ));
    s.push((
        "crash at every update boundary; a fresh supervisor recovers",
        chaos_recovery,
    ));
    s.push((
        "crash before and after every rollback boundary; recovery remains resumable",
        rollback_chaos_recovery,
    ));
    s
}

fn run_suite() -> R {
    let ctx = Ctx::new()?;
    step("build workspace binaries");
    ctx.build()?;
    // Build the two application versions once; scenarios reuse them.
    let app_v1 = ctx.build_app("1.0.0")?;
    let app_v2 = ctx.build_app("2.0.0")?;
    if sha256_hex(&app_v1)? != sha256_hex(&app_v2)? {
        return fail(
            "sample app binaries differ; release identity must come only from bundle config",
        );
    }
    // Two distinguishable supervisor builds for the self-update scenarios.
    ctx.build_supervisor("1.0.0")?;
    ctx.build_supervisor("2.0.0")?;
    ctx.build_post_ready_crashing_supervisor("2.0.0")?;

    // Every scenario owns a unique working dir and unique ports, so they are safe to
    // run concurrently on a bounded worker pool. They are blocking process work
    // (spawn, poll HTTP, sleep), not async I/O, so plain threads fit; an async runtime
    // would only wrap the same blocking work in a thread pool. Override the degree with
    // E2E_JOBS (E2E_JOBS=1 gives the old sequential order for debugging). The whole run
    // completes even when a scenario fails, so one run reports every failure.
    let mut scenarios = scenarios();
    if let Ok(filter) = std::env::var("E2E_FILTER") {
        scenarios.retain(|(name, _)| name.contains(&filter));
        if scenarios.is_empty() {
            return fail(format!("E2E_FILTER matched no scenarios: {filter}"));
        }
    }
    let n = scenarios.len();
    let jobs = job_count(n);
    step(&format!("running {n} scenarios, up to {jobs} at a time"));

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(&'static str, R)>> = Mutex::new(Vec::new());
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&(name, scenario)) = scenarios.get(i) else {
                    break;
                };
                let began = Instant::now();
                // A panicking scenario becomes a failure, not an aborted run.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenario(&ctx)))
                    .unwrap_or_else(|_| fail("scenario panicked"));
                let secs = began.elapsed().as_secs_f64();
                match &res {
                    Ok(()) => println!("\x1b[1;32mPASS\x1b[0m ({secs:>5.1}s) {name}"),
                    Err(e) => println!(
                        "\x1b[1;31mFAIL\x1b[0m ({secs:>5.1}s) {name}: {e}{}",
                        dump_install_state(&ctx.work)
                    ),
                }
                results.lock().unwrap().push((name, res));
            });
        }
    });

    let results = results.into_inner().unwrap();
    let failures: Vec<&str> = results
        .iter()
        .filter_map(|(name, r)| r.is_err().then_some(*name))
        .collect();
    println!(
        "\n{} of {n} scenarios passed in {:.1}s",
        n - failures.len(),
        start.elapsed().as_secs_f64()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} scenario(s) failed: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

/// Degree of parallelism: `E2E_JOBS` when set (clamped to at least 1), else the
/// machine's parallelism capped at four so a run does not massively oversubscribe —
/// each scenario itself spawns a handful of processes. Never more than the scenario
/// count.
fn job_count(n: usize) -> usize {
    let n = n.max(1);
    if let Ok(Ok(j)) = std::env::var("E2E_JOBS").map(|v| v.parse::<usize>()) {
        return j.clamp(1, n);
    }
    let cpus = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);
    default_job_count(n, cpus)
}

fn default_job_count(scenarios: usize, cpus: usize) -> usize {
    scenarios.max(1).min(cpus.max(1)).min(4)
}

fn step(msg: &str) {
    println!("\n\x1b[1;36m== {msg} ==\x1b[0m");
}
fn ok(msg: &str) {
    println!("\x1b[1;32m{msg}\x1b[0m");
}

#[cfg(test)]
mod tests {
    use super::default_job_count;

    #[test]
    fn default_e2e_parallelism_is_bounded_by_scenarios_cpus_and_four() {
        assert_eq!(default_job_count(16, 12), 4);
        assert_eq!(default_job_count(16, 2), 2);
        assert_eq!(default_job_count(3, 12), 3);
        assert_eq!(default_job_count(0, 0), 1);
    }
}
