//! Arbitrary-`SIGKILL` fuzzer for the cold-install / broken-rollout / roll-forward / interleave
//! crash-safety paths.
//!
//! The deterministic `install_chaos_recovery` / `stateless_install_chaos` scenarios crash at every
//! *named* state-machine boundary — that's the exhaustive proof *under the atomicity invariant*
//! (every durable write is atomic, so a crash between boundaries is equivalent to a crash at one).
//! This fuzzer is the adversarial check that the invariant actually holds *everywhere*: it kills the
//! whole stack at truly arbitrary instants, which is the one thing that catches a durable write we
//! forgot to make atomic (or a boundary we forgot to place), and it models real pod-kill timing.
//!
//! It runs four sequential rounds, each a full burst of arbitrary kills, so the fuzz spans the
//! whole fleet lifecycle — the story is: 1.0.0 installs, a broken 2.0.0 begins rolling out, a
//! healthy 3.0.0 supersedes the failing 2.0.0 mid-rollout (the node must end up on 3.0.0), and then
//! the same supersession is replayed against a broken transaction still in-flight on disk.
//!
//! - `install` — a cold node must reconverge to a live, committed 1.0.0. Only this round wipes the
//!   disk (emptyDir restart churn); an upgrade never does.
//! - `broken-rollout` — the head is re-signed to a 2.0.0 that stages and verifies but whose
//!   entrypoint cannot exec (a signed bundle with a broken executable, exactly like the fleet e2e's
//!   broken rollout versions — NOT an ingest-malformed archive). The node ACTIVATES it, the launch
//!   fails, and it rolls back to the committed 1.0.0 and holds there. Persistent disk — no wipes.
//! - `roll-forward` — a healthy 3.0.0 supersedes the failing 2.0.0 head; the node must abandon the
//!   broken 2.0.0 and converge to a live, committed 3.0.0. Persistent disk — no wipes.
//! - `interleave` — the true-race round: a broken head is superseded by a healthy one *while its
//!   update transaction is still in-flight on disk*. Each trial waits for THIS trial's fresh broken
//!   rollout to begin (the `-> {broken_v}` log, not a bare journal — a prior trial can leave a stale
//!   committed journal behind), SIGKILLs the tree the instant its transaction journal lands,
//!   publishes the healthy successor while the node is DOWN, then boots — forcing recovery to
//!   reconcile an in-flight broken journal against a head that already moved on. It must reject the
//!   broken release, restore the predecessor, and roll forward to the healthy successor (versions
//!   climb 3→5→7→9). Persistent disk — no wipes.
//!
//! We do NOT publish 3.0.0 until the node has provably BEGUN the 2.0.0 rollout (a clean stack is
//! run first and gated on the `applying update … -> 2.0.0` log). Otherwise 3.0.0 would pre-empt an
//! un-attempted 2.0.0 and the node would jump straight to 3.0.0, never exercising the rollback. The
//! `interleave` round is the stronger form of that same guarantee: it publishes the healthy
//! successor only after the broken transaction is provably journaled and in-flight.
//!
//! Deleting the disk on an upgrade round would turn the upgrade into a fresh cold-install and never
//! exercise the roll-forward-from-committed-state path, so only the install round is allowed to.
//!
//! It lives in its own binary — never inside the e2e concurrent scenario pool — so its aggressive
//! whole-tree kills can never starve or collide with other scenarios. It reuses the e2e harness
//! library for the (fragile, single-source-of-truth) TUF + launcher setup and adds only the kill
//! loop. Run: `cargo run -p killfuzz` (tune with `KILLFUZZ_ROUNDS` / `KILLFUZZ_SEED`).

use e2e::fixture;
use e2e::fixtures::*;
use e2e::harness::*;
use std::path::Path;
use std::process::Command;

fn main() {
    if fixture::dispatch_if_invoked() {
        return;
    }

    match run() {
        Ok(()) => println!("\n\x1b[1;32mkillfuzz: OK\x1b[0m"),
        Err(e) => {
            eprintln!("\n\x1b[1;31mkillfuzz FAIL: {e}\x1b[0m");
            std::process::exit(1);
        }
    }
}

/// A tiny deterministic PRNG so a failing run is reproducible from its seed.
struct Lcg(u64);
impl Lcg {
    fn step(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + (self.step() >> 33) % (hi - lo)
    }
    fn bit(&mut self) -> bool {
        (self.step() >> 40) & 1 == 1
    }
}

/// End the round's straggler workload WITHOUT touching the mock-CDN server. `Service::drop` already
/// killed the launcher's process group, which takes the agent with it; what remains is the
/// hook-managed workload, which lives in a session of its own precisely so no agent restart can
/// disturb it. The reconciler recorded its PID, so it is stopped by identity rather than by
/// pattern-matching argv — through the same guard every scenario's teardown uses.
fn reap(dir: &Path) {
    fixture::workload(dir).stop();
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| match v.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => v.parse().ok(),
        })
        .unwrap_or(default)
}

/// One kill-fuzz round: `rounds` arbitrary SIGKILLs, then an untouched boot that must reconverge to
/// a live, committed `expect`. The whole stack is respawned and killed each iteration. When
/// `wipe_disk` is set (the cold-install round only), half the iterations wipe the install first
/// (stateless emptyDir → fresh cold-install), half leave state to recover; an upgrade round never
/// wipes — deleting the disk would turn it into a fresh install, not an upgrade.
struct FuzzPhase<'a> {
    label: &'a str,
    expect: &'a str,
    wipe_disk: bool,
    rounds: usize,
}

/// The one node installation a sequence of fuzz phases kills and recovers. Keeping its command,
/// durable paths, service endpoint and seed together prevents a phase from observing a different
/// node than the one it killed.
struct FuzzHarness<'a> {
    seed: u64,
    cmd: &'a Command,
    dir: &'a Path,
    install: &'a Path,
    state_path: &'a Path,
    svc: &'a str,
    ver_url: &'a str,
}

impl FuzzHarness<'_> {
    fn run_phase(&self, phase: FuzzPhase<'_>, rng: &mut Lcg) -> R {
        let FuzzPhase {
            label,
            expect,
            wipe_disk,
            rounds,
        } = phase;
        let Self {
            seed,
            cmd,
            dir,
            install,
            state_path,
            svc,
            ver_url,
        } = *self;
        println!("killfuzz [{label}]: {rounds} rounds of arbitrary SIGKILL → expect a live, committed {expect}");
        for round in 0..rounds {
            // On the install round, half the iterations are stateless (emptyDir wipe → fresh
            // cold-install), half stateful (state survives → journal recovery). Upgrade rounds keep
            // the disk on every iteration so the roll-forward-from-committed-state path is exercised.
            let stateless = wipe_disk && rng.bit();
            if stateless {
                let _ = std::fs::remove_dir_all(install);
            }
            let stack = Service::spawn("killfuzz", cmd);
            // Kill at a random instant spanning the install/upgrade/reject/confirm/steady window.
            let kill_ms = rng.range(150, 3500);
            std::thread::sleep(std::time::Duration::from_millis(kill_ms));

            // A brick is never acceptable at any kill timing: a healthy floor (1.0.0, later 2.0.0)
            // always exists at or below the assigned head, so recovery can never run out of targets.
            if stack.log_contains("no installable application") {
                let log = stack.captured_log();
                drop(stack);
                reap(dir);
                return fail(format!(
                "phase {label} round {round} ({}, killed at {kill_ms}ms, seed {seed:#x}): stranded on \
                 'no installable application' — a kill must never brick a node with a healthy floor:\n{log}",
                if stateless { "stateless" } else { "stateful" }
            ));
            }

            // SIGKILL the WHOLE tree, then reap synchronously: `Service::drop` kills the launcher's
            // process group (taking the agent with it) and joins its monitor; `reap` ends the
            // hook-managed workload while leaving the mock-CDN server up.
            drop(stack);
            reap(dir);
            // Do not start the next round until the tree is actually gone (service port released).
            if !wait_until(STOP_TIMEOUT, || http_text(ver_url).is_none()) {
                return fail(format!(
                "phase {label} round {round}: the node stack was not fully reaped (service port still held) after the kill"
            ));
            }
        }

        // An untouched boot must reconverge to this phase's expected live, committed version — proving
        // no round's kill left durable state that bricks recovery or strands the wrong release.
        let stack = Service::spawn("killfuzz", cmd);
        let live = wait_for_version(svc, expect, CONVERGE_TIMEOUT);
        let want = expect.to_string();
        let settled = wait_until(CONVERGE_TIMEOUT, || {
            matches!(
                updated::state::read_installed(state_path),
                updated::state::Installed::Present(ref s) if s.release.version == want
            )
        });
        let log = stack.captured_log();
        drop(stack);
        reap(dir);
        if !live || !settled {
            return fail(format!(
                "phase {label}: after {rounds} arbitrary SIGKILLs (seed {seed:#x}) the node never \
             reconverged to a live, committed {expect} (live={live}, settled={settled}):\n{log}"
            ));
        }
        // Release the port before the next phase respawns the stack.
        if !wait_until(STOP_TIMEOUT, || http_text(ver_url).is_none()) {
            return fail(format!(
            "phase {label}: the settle boot's tree was not fully reaped (service port still held)"
        ));
        }
        println!("killfuzz [{label}]: reconverged to a live, committed {expect}");
        Ok(())
    }
}

fn run() -> R {
    // Its own lock (`target/killfuzz.lock`) + workdir (`target/killfuzz-work`), so it never blocks
    // on or clobbers the e2e suite and the two can run concurrently.
    let ctx = Ctx::named("killfuzz")?;
    // Silent for a couple of minutes on a cold target — say so, so it doesn't look hung.
    println!("killfuzz: building workspace binaries + sample app (first run is slow)…");
    ctx.build()?;
    // `ctx.build()` builds the server, agent and launcher binaries; the versioned sample app is a separate
    // fixture the e2e runner builds explicitly, so build it here too or the publish has no source.
    // One version-agnostic binary serves every release — the version is baked into each signed
    // bundle's config, so the same bytes publish as 1.0.0, 2.0.0, and 3.0.0.
    ctx.build_app("1.0.0")?;

    let dir = ctx.work.join("killfuzz");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    // Round 1 starts with only a healthy 1.0.0 floor and ordered-install fallback signed in. The
    // corrupt 2.0.0 and healthy 3.0.0 heads are published live BETWEEN rounds (below), which re-signs
    // the assignment in place, so the running stack rolls forward exactly as a fleet push would.
    ctx.publish(&dir, "app", "1.0.0", &app_v(&ctx, "1.0.0"))?;

    let (srv, svc) = ("127.0.0.1:21990", "127.0.0.1:21991");
    let server = ctx.serve(&dir, srv)?;
    let cmd = Node::new(&ctx, &dir, srv, "app")
        .cold_install()
        .workload(svc)
        .ordered_install_fallback()
        .check_interval("1s")
        .health_grace("2s")
        // A short confirmation window (default is 120s) so a committed update confirms quickly
        // instead of blocking the next one. The `interleave` round in particular can only begin a
        // fresh broken rollout once the current version is confirmed — the agent refuses to
        // start a new update while one is still unconfirmed in its window. The killfuzz exercises
        // crash-safety of install/rollback/roll-forward/reconcile, not the window's duration.
        .confirmation_window("3s")
        .launcher()?;

    // The canonical layout, never a second copy of it: a hand-written state path keeps passing
    // after the real layout moves, because the file it watches is simply never written.
    let paths = e2e::harness::node_paths(&dir);
    let install = paths.install_root.clone();
    let state_path = paths.installed.clone();
    let ver_url = format!("http://{svc}/version");
    let rounds = env_u64("KILLFUZZ_ROUNDS", 12) as usize;
    let seed = env_u64("KILLFUZZ_SEED", 0x00C0_FFEE_D00D);
    let mut rng = Lcg(seed);
    let fuzz = FuzzHarness {
        seed,
        cmd: &cmd,
        dir: &dir,
        install: &install,
        state_path: &state_path,
        svc,
        ver_url: &ver_url,
    };

    println!(
        "killfuzz: 4 rounds — install→1.0.0, broken 2.0.0 rollout→rolls back to 1.0.0, healthy \
         3.0.0 supersedes→3.0.0 ({rounds} kill rounds each), then interleave \
         ({INTERLEAVE_TRIALS} trials, one kill each, climbing 3→5→7→9) (seed {seed:#x})"
    );

    // Round 1 — cold install. Assignment head is 1.0.0; a kill at any instant of
    // cold-install/confirm/steady must reconverge to a live, committed 1.0.0. This is the only round
    // that wipes the disk (emptyDir restart churn).
    fuzz.run_phase(
        FuzzPhase {
            label: "install",
            expect: "1.0.0",
            wipe_disk: true,
            rounds,
        },
        &mut rng,
    )?;

    // Round 2 — a broken 2.0.0 begins rolling out. Its bundle stages and verifies (a valid, signed
    // archive) but its entrypoint cannot exec — exactly like the fleet e2e's broken rollout versions — so
    // the node ACTIVATES it, the launch fails, and it rolls back to the committed 1.0.0. Publishing
    // it re-signs the live assignment head to 2.0.0. Persistent disk — no wipes; a kill at any
    // instant of the rollout/rollback must still leave a live, committed 1.0.0.
    let broken = dir.join("broken-app");
    std::fs::write(&broken, b"not-a-runnable-application-entrypoint\n").map_err(str_err)?;
    ctx.publish(&dir, "app", "2.0.0", &broken)?;

    // Gate: prove the node actually BEGINS rolling out 2.0.0 before 3.0.0 is ever published. A clean
    // stack is run and waited on for the durable `applying update 1.0.0 -> 2.0.0` log (a broken
    // executable makes the rollback that follows inevitable). Without this, publishing 3.0.0 could
    // pre-empt an un-attempted 2.0.0 and the node would jump straight to 3.0.0, never exercising the
    // rollback — the whole point of the round.
    {
        let stack = Service::spawn("killfuzz", &cmd);
        let started = wait_until(CONVERGE_TIMEOUT, || {
            stack.log_contains("applying update 1.0.0 -> 2.0.0")
        });
        let log = stack.captured_log();
        drop(stack);
        // The next phase rebinds the same port, so the wait for the old listener to disappear is a
        // precondition, not a diagnostic: discarding its result meant the phase could start against
        // a port the previous stack still held and fail for an unrelated reason.
        if !wait_until(STOP_TIMEOUT, || http_text(&ver_url).is_none()) {
            drop(server);
            return fail(
                "round 2: the previous stack never released its listener, so the next phase would \
                 race it for the port"
                    .to_string(),
            );
        }
        if !started {
            drop(server);
            return fail(format!(
                "round 2: the node never began rolling out the broken 2.0.0 head (no `applying \
                 update 1.0.0 -> 2.0.0`); cannot test supersession because 3.0.0 would just pre-empt \
                 an un-attempted 2.0.0:\n{log}"
            ));
        }
    }
    println!("killfuzz [broken-rollout]: node began the 2.0.0 rollout — 3.0.0 will not be published until now");

    fuzz.run_phase(
        FuzzPhase {
            label: "broken-rollout",
            expect: "1.0.0",
            wipe_disk: false,
            rounds,
        },
        &mut rng,
    )?;

    // Round 3 — a healthy 3.0.0 supersedes the failing 2.0.0 head. Only now — after the node has
    // provably engaged the 2.0.0 rollout above — is 3.0.0 published, moving the head above the
    // broken 2.0.0; the node must abandon 2.0.0 and roll forward to a live, committed 3.0.0.
    // Persistent disk — no wipes.
    ctx.publish(&dir, "app", "3.0.0", &app_v(&ctx, "1.0.0"))?;
    fuzz.run_phase(
        FuzzPhase {
            label: "roll-forward",
            expect: "3.0.0",
            wipe_disk: false,
            rounds,
        },
        &mut rng,
    )?;

    // Round 4 — TRUE INTERLEAVE: a broken head is superseded by a healthy one *while the broken
    // update transaction is still in-flight on disk*. This is the one window rounds 2-3 never hit —
    // there, the broken 2.0.0 was fully rejected before 3.0.0 was published, so recovery never had
    // to reconcile an in-flight broken journal against a head that had already moved on. Here we
    // force exactly that and prove `reconcile_transaction` finalizes the broken rollback (rejects it,
    // restores the predecessor) before rolling forward, no matter where the SIGKILL lands.
    //
    // Each trial uses a fresh broken head with unique bytes and an ascending version, so no stale
    // rejection or version floor carries between trials (the node climbs 3→5→7→9).
    let journal_path = paths.journal.clone();
    const INTERLEAVE_TRIALS: usize = 3;
    for trial in 0..INTERLEAVE_TRIALS {
        let broken_v = format!("{}.0.0", 4 + 2 * trial);
        let healthy_v = format!("{}.0.0", 5 + 2 * trial);
        // Fresh broken bytes → a new archive hash → never a stale rejection from a prior trial. The
        // bundle stages and verifies but its entrypoint cannot exec, so activating it fails.
        let broken = dir.join(format!("interleave-broken-{trial}"));
        std::fs::write(
            &broken,
            format!("not-a-runnable-application-entrypoint trial {trial}\n"),
        )
        .map_err(str_err)?;
        ctx.publish(&dir, "app", &broken_v, &broken)?;

        // Bring the broken update in-flight, then SIGKILL the tree with its transaction journal on
        // disk. Gate on THIS trial's fresh rollout log (`-> {broken_v}`) first, NOT on bare
        // `journal_path.exists()`: the previous trial's settle stack can be torn down in the window
        // after it commits an update but before it clears the spent journal, leaving a stale
        // committed journal on disk. Keying off bare journal existence would fire on that stale
        // journal — before the broken rollout even starts (the just-committed version is still
        // unconfirmed, so the agent will not begin a new update yet) — and recovery would then
        // reconcile the stale version instead of {broken_v}. Waiting for `-> {broken_v}` means the
        // gate stack has already cleared the stale journal and confirmed the predecessor, so the
        // journal we then catch belongs to {broken_v}.
        let stack = Service::spawn("killfuzz", &cmd);
        let began = wait_until(CONVERGE_TIMEOUT, || {
            stack.log_contains(&format!("-> {broken_v}"))
        });
        // Tight-poll for the fresh journal (written at Activating, before the entrypoint even
        // execs) and SIGKILL the instant it lands — before the failed activation can roll up and a
        // Service restart's recovery can clear it, freezing a genuine in-flight transaction on disk.
        let in_flight = began && {
            let mut seen = false;
            for _ in 0..1200 {
                if journal_path.exists() {
                    seen = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            seen
        };
        if !in_flight {
            let log = stack.captured_log();
            drop(stack);
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: the broken {broken_v} update never went in-flight \
                 (began={began}); cannot stage the reconcile-against-moved-head race:\n{log}"
            ));
        }

        // SIGKILL the whole tree with the broken transaction still journaled, then reap the
        // straggler workload. The hook-managed workload lives in a session of its own, so the
        // group kill never reaches it: whether one is still serving here depends on where the
        // broken activation was interrupted (its drain stops the predecessor's workload before the
        // entrypoint it cannot exec), and a round that only passes when the kill lands after the
        // drain is a race, not a test.
        drop(stack);
        reap(&dir);
        if !wait_until(STOP_TIMEOUT, || http_text(&ver_url).is_none()) {
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: stack tree not reaped after the mid-flight kill"
            ));
        }
        // The in-flight broken journal must have survived the kill — that durable record is what
        // forces recovery to reconcile. Now move the head to the healthy successor while the node is
        // DOWN, so the next boot reconciles an in-flight broken journal against an already-moved head.
        if !journal_path.exists() {
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: the in-flight {broken_v} journal did not survive the kill; \
                 the reconcile-against-moved-head window was not created"
            ));
        }
        ctx.publish(&dir, "app", &healthy_v, &app_v(&ctx, "1.0.0"))?;

        // Boot into recovery. Journal-driven, it must finalize the broken transaction (reject/restore
        // the predecessor) and then roll forward to a live, committed healthy_v.
        let stack = Service::spawn("killfuzz", &cmd);
        let live = wait_for_version(svc, &healthy_v, CONVERGE_TIMEOUT);
        let want = healthy_v.clone();
        let settled = wait_until(CONVERGE_TIMEOUT, || {
            matches!(
                updated::state::read_installed(&state_path),
                updated::state::Installed::Present(ref s) if s.release.version == want
            )
        });
        // Prove recovery actually reconciled the in-flight broken transaction (rather than the node
        // simply never having engaged the broken head): a recovery line must name broken_v. Which
        // classification fires depends on where the kill landed, so accept any of them.
        let reconciled = stack.log_contains(&format!(
            "recovery: rejected {broken_v} after failed activation"
        )) || stack.log_contains(&format!("interrupted activation of {broken_v}"))
            || stack.log_contains(&format!("activation of {broken_v} never landed"))
            || stack.log_contains(&format!("completing rollback from {broken_v}"));
        let log = stack.captured_log();
        // The settle boot converged onto a healthy release, so its hook started a workload — which
        // outlives the stack's process group by construction. Reap it, exactly as every phase's
        // settle boot does, or the next trial's stack meets the service address already bound.
        drop(stack);
        reap(&dir);
        if !live || !settled {
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: after killing the in-flight {broken_v} update and moving the \
                 head to {healthy_v}, the node never reconverged to a live, committed {healthy_v} \
                 (live={live}, settled={settled}):\n{log}"
            ));
        }
        if !reconciled {
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: the node reached {healthy_v} but its recovery log never \
                 reconciled the in-flight {broken_v} transaction — the moved-head reconcile path was \
                 not exercised (its coverage is the whole point of this round):\n{log}"
            ));
        }
        if !wait_until(STOP_TIMEOUT, || http_text(&ver_url).is_none()) {
            drop(server);
            return fail(format!(
                "round 4 trial {trial}: settle stack not reaped (service port still held)"
            ));
        }
        println!(
            "killfuzz [interleave]: trial {trial}: killed the in-flight {broken_v} update, moved the \
             head to {healthy_v} while down, and recovery reconciled + rolled forward to {healthy_v}"
        );
    }

    drop(server);
    println!(
        "killfuzz: survived cold-install (1.0.0), a broken 2.0.0 rollout that rolled back (held on \
         1.0.0), a healthy 3.0.0 that superseded it (→3.0.0), and {INTERLEAVE_TRIALS} in-flight \
         broken-transaction kills each reconciled against an already-moved head (climbed 3→5→7→9)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_fixture_dispatch_cannot_reenter_the_fuzzer() {
        assert!(fixture::is_invocation([
            "killfuzz",
            "apply",
            "--",
            "--lifecycle-fixture",
        ]));
        assert!(!fixture::is_invocation(["killfuzz"]));
    }
}
