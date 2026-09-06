#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! End-to-end test / demo. One cross-platform Rust binary — instead of parallel
//! bash and PowerShell scripts that inevitably drift — that builds the release
//! binaries, stands up a real TUF repository via the `server`, and drives real
//! application-update, rollback, externally supervised agent restart, crash-recovery, and
//! TUF/hardening scenarios against them. Platform-specific behaviour lives behind
//! `#[cfg(...)]`, not in a second script.
//!
//! The workload in these scenarios belongs to the release's own reconciler — the fixture in
//! `e2e::fixture`, which this binary also *is*: the agent invokes this same executable as the
//! signed hook. The agent never launches, holds, or stops a workload process anywhere in the suite.
//!
//! Run: `cargo run -p e2e`. Exit 0 means every scenario passed. Scenarios are
//! independent (unique dirs + ports) and run on a bounded thread pool; set
//! `E2E_JOBS=1` to run them one at a time in order.

mod scenarios;

pub use e2e::fixture;
pub use e2e::fixtures::*;
pub use e2e::harness::*;
use scenarios::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn main() {
    if fixture::dispatch_if_invoked() {
        return;
    }
    if let Err(e) = run_suite() {
        eprintln!("\x1b[1;31mFAIL: {e}\x1b[0m");
        std::process::exit(1);
    }
    println!("\n\x1b[1;32mSUCCESS: all scenarios passed\x1b[0m");
}

/// A named scenario. To add one: write an `fn(&Ctx) -> R` that asserts its own
/// behaviour (returning `Err` on failure), then add a line to `scenarios()`.
type Scenario = (&'static str, fn(&Ctx) -> R);

fn scenarios() -> Vec<Scenario> {
    let mut s: Vec<Scenario> = vec![
        ("complex release graph routes and multi-hop rollback survive restart", complex_release_graph_and_multihop_rollback),
        ("an update that becomes unhealthy during confirmation is rolled back", unhealthy_unconfirmed_release_rolls_back),
        ("routine convergence runs health gates even when its cadence is shorter than the grace", routine_convergence_keeps_running_health_gates),
        (
            "the reconciler converges the workload v1->v2, and a broken v3 is rolled back",
            app_update_and_rollback,
        ),
        (
            "a hook-performed upgrade drops zero requests behind a readiness-aware load balancer",
            zero_downtime_upgrade,
        ),
        (
            "a cold node installs its first payload and the reconciler starts it",
            cold_install_applies_the_first_release,
        ),
        (
            "the install machine hands off cleanly to the update machine (no journal overlap)",
            cold_install_hands_off_to_update,
        ),
        (
            "an unconfirmed release that fails its boot health gate is reverted and rejected, while a confirmed one is only reported",
            crash_evidence_reverts_only_the_unconfirmed,
        ),
        (
            "the healthcheck hook fails closed across distinct workload fault modes",
            chaotic_application_health_failures,
        ),
        (
            "a failed first installation never substitutes an older target",
            cold_install_rejects_broken_target,
        ),
        (
            "a cold node fails closed when every cold-install candidate has been rejected",
            cold_install_fails_closed_when_every_candidate_is_rejected,
        ),
        (
            "a malformed target blocks installation before activation",
            cold_install_rejects_corrupt_target,
        ),
        (
            "two nodes receive one group release; only the failing node rolls back",
            group_peer_failure_is_node_local,
        ),
        (
            "a tampered enrollment trust root fails closed before any hook runs",
            tampered_root_fails_closed,
        ),
        (
            "a signed local deployment repairs a modified bundle with no network",
            signed_local_repair_without_network,
        ),
        ("a second agent on the same install is refused", single_instance_lock),
        (
            "a health-check-failed release stays rejected across a restart",
            persisted_rejection,
        ),
        ("a reconciler converge failure rolls back", provider_converge_failure),
        (
            "an interrupted converge is compensated under its own attempt id and lands exactly once",
            converge_replay_converges_exactly_once,
        ),
        ("a reconciler healthcheck failure rolls back", provider_healthcheck_failure),
        ("a reconciler rollback failure remains recoverable", provider_rollback_failure),
        ("a wedged reconciler operation is bounded by its timeout", provider_hook_hangs_are_bounded),
        (
            "a migration-gated stateful upgrade wrapper completes every lifecycle step",
            migration_shaped_upgrade,
        ),
        (
            "an install switches sample app -> migration-shaped release -> sample app",
            sample_to_migration_shaped_and_back,
        ),
        (
            "a failed migration restores its archive and content backup",
            migration_shaped_failed_migration_rolls_back,
        ),
        (
            "an agent crash never disturbs the hook-managed workload; the service restarts the agent",
            agent_crash_never_disturbs_the_workload,
        ),
    ];
    // Unix-only mechanisms (file modes; a shell entrypoint for the never-healthy head).
    #[cfg(unix)]
    {
        s.push(("the TUF role keys are owner-only (0600)", key_perms));
        s.push((
            "the reconciler healthcheck gates first install and upgrade",
            lifecycle_healthcheck_gates_readiness,
        ));
    }
    // Chaos recovery runs last: it replays every transaction boundary, so it is by
    // far the slowest scenario.
    s.push((
        "crash at every cold-install boundary; recovery completes the first install",
        install_chaos_recovery,
    ));
    s.push((
        "crash at every update boundary; a fresh agent recovers",
        chaos_recovery,
    ));
    s.push((
        "crash before and after every rollback boundary; recovery remains resumable",
        rollback_chaos_recovery,
    ));
    s.push((
        "a reboot mid-rollback bounds lost predecessor health without repeating deployment",
        a_reboot_mid_rollback_bounds_lost_predecessor_health,
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
