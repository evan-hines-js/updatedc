use super::*;
use crate::store::MemStore;

#[test]
fn jitter_stays_within_band() {
    let base = Duration::from_secs(100);
    let j = jitter(base, 20);
    assert!(j >= Duration::from_secs(80) && j <= Duration::from_secs(120));
    assert_eq!(jitter(base, 0), base);
}

#[test]
fn network_backoff_is_exponential_and_capped() {
    let base = Duration::from_secs(15);
    assert_eq!(network_backoff(base, 0), base);
    assert_eq!(network_backoff(base, 3), Duration::from_secs(120)); // 15 * 2^3
    assert_eq!(network_backoff(base, 100), Duration::from_secs(15 * 60)); // capped
}

#[test]
fn reload_health_requires_the_candidate_version() {
    assert!(health_headers_match(
        "token",
        Some("2.0.0"),
        Some("token"),
        Some("2.0.0")
    ));
    assert!(
        !health_headers_match("token", Some("2.0.0"), Some("token"), Some("1.0.0")),
        "a successful no-op reload must not validate the old executable"
    );
    assert!(!health_headers_match(
        "token",
        Some("2.0.0"),
        Some("token"),
        None
    ));
}

#[test]
fn application_updates_wait_for_pending_confirmation() {
    let now = Instant::now();
    assert!(!application_check_due(true, true, now, now));
    assert!(application_check_due(true, false, now, now));
}

// ------------------------ transaction reconciliation (Store) ------------------------

/// Exercise recovery through the production boot planner/executor. There is deliberately
/// no second live-reconciliation helper: every retry re-enters this same path.
fn recover_through_boot(store: &mut dyn Store) -> io::Result<()> {
    let situation = Situation {
        installed: store.installed(),
        baseline: None,
        disk_sha: store.binary_sha(),
        old_sha: store.rollback_sha(),
        journal: store.journal()?,
        app_crashed: false,
        app_running: None,
        bad_supervisor: None,
        confirm_window: Duration::from_secs(120),
        now: 1_000_000,
    };
    let plan = plan_boot(&situation);
    if let Some(reason) = plan.fail_closed {
        return Err(io::Error::other(reason));
    }
    apply_store_plan(&plan, store)
}

/// A journal recording a `from -> to` swap of `old` -> `new` bytes.
fn tx(old: &str, new: &str, to: &str, from: &str) -> Transaction {
    Transaction {
        old_sha256: old.into(),
        new_sha256: new.into(),
        to_version: to.into(),
        from_version: Some(from.into()),
    }
}

#[test]
fn reconcile_reverses_an_unrecorded_commit() {
    // The binary was swapped to NEW but the state still records the OLD version: the commit
    // did not land. Reconcile reverses to the committed binary and clears the journal.
    let mut store = MemStore::committed("1.0.0", "OLD");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    store.set_journal(tx("OLD", "NEW", "2.0.0", "1.0.0"));
    recover_through_boot(&mut store).unwrap();
    assert_eq!(
        store.binary_sha().as_deref(),
        Some("OLD"),
        "reverses to committed"
    );
    assert!(!store.journal_present());
    assert!(!store.has_rollback());
}

#[test]
fn reconcile_confirms_a_recorded_commit() {
    // The state already records NEW (2.0.0): the commit landed, only the journal deletion
    // was left. Reconcile keeps NEW and clears the journal; the rollback image stays for
    // the pending machinery to confirm or revert.
    let mut store = MemStore::committed("2.0.0", "NEW");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    store.set_journal(tx("OLD", "NEW", "2.0.0", "1.0.0"));
    recover_through_boot(&mut store).unwrap();
    assert_eq!(
        store.binary_sha().as_deref(),
        Some("NEW"),
        "keeps the committed binary"
    );
    assert!(!store.journal_present());
    assert!(store.has_rollback());
}

#[test]
fn reconcile_is_a_noop_without_a_journal() {
    let mut store = MemStore::committed("2.0.0", "NEW");
    recover_through_boot(&mut store).unwrap();
    assert_eq!(store.binary_sha().as_deref(), Some("NEW"));
}

#[test]
fn a_failed_restore_leaves_the_journal_for_the_next_boot() {
    // If the atomic binary restore fails mid-recovery (a torn write), the journal must
    // survive so the next boot retries — the transaction is never silently lost.
    let mut store = MemStore::committed("1.0.0", "OLD");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    store.set_journal(tx("OLD", "NEW", "2.0.0", "1.0.0"));
    store.faults.restore = true;
    assert!(recover_through_boot(&mut store).is_err());
    assert!(
        store.journal_present(),
        "the journal survives a failed restore, so recovery retries rather than losing the update"
    );
}

// --------------------------- boot plan execution (Store) ---------------------------
//
// The boot planner's *decision* is proved in `boot`; these prove the executor performs a
// plan's durable half correctly against the Store.

#[test]
fn executing_a_revert_plan_restores_rejects_and_commits() {
    // The crash-loop revert plan: restore the rollback image to the predecessor, commit it,
    // and reject the crashing release's bytes.
    let mut store = MemStore::committed("2.0.0", "NEW");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    let plan = Plan {
        binary: BinaryFix::RestoreCommitted { sha: "OLD".into() },
        commit: Some(InstalledState::confirmed("1.0.0".into(), "OLD".into())),
        reject_app: vec!["NEW".into()],
        ..Default::default()
    };
    apply_store_plan(&plan, &mut store).unwrap();
    assert_eq!(
        store.binary_sha().as_deref(),
        Some("OLD"),
        "reverted to the predecessor"
    );
    assert_eq!(
        store.installed_state().map(|s| s.version.as_str()),
        Some("1.0.0")
    );
    assert!(store.is_rejected("NEW"), "the crashing release is rejected");
    assert!(!store.has_rollback());
}

#[test]
fn executing_a_confirm_plan_clears_pending_and_drops_the_image() {
    let mut store = MemStore::committed("2.0.0", "NEW");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    let plan = Plan {
        commit: Some(InstalledState::confirmed("2.0.0".into(), "NEW".into())),
        drop_rollback: true,
        ..Default::default()
    };
    apply_store_plan(&plan, &mut store).unwrap();
    assert!(
        !store.has_rollback(),
        "confirmation drops the rollback image"
    );
    assert!(store.installed_state().unwrap().pending.is_none());
}

#[test]
fn a_revert_commits_the_predecessor_before_the_destructive_restore() {
    // The boot revert has no journal covering it, and `restore_committed` destroys the
    // rollback image. If a crash lands between the restore and the commit, the state must
    // already record the predecessor so the next boot's drift-check recovers. Prove the
    // ordering: with the restore faulted, the predecessor commit has already landed and the
    // rollback image is untouched (so the failed step is retryable), never fail-closed.
    let mut store = MemStore::committed("2.0.0", "NEW");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    store.faults.restore = true;
    let plan = Plan {
        binary: BinaryFix::RestoreCommitted { sha: "OLD".into() },
        commit: Some(InstalledState::confirmed("1.0.0".into(), "OLD".into())),
        reject_app: vec!["NEW".into()],
        ..Default::default()
    };
    assert!(
        apply_store_plan(&plan, &mut store).is_err(),
        "the faulted restore fails the plan"
    );
    assert_eq!(
        store.installed_state().map(|s| s.version.as_str()),
        Some("1.0.0"),
        "the predecessor was committed BEFORE the destructive restore, so a crash here recovers"
    );
    assert!(
        store.has_rollback(),
        "the restore never ran, so the rollback image survives for the next boot"
    );
}

// ------------------------ the full transaction (Control + Health ports) ------------------------
//
// `apply_update` drives the durable [`Store`] plus the live-application ports. With a
// `MemStore` (fault-injectable) and a scripted `FakeTower`, every branch — commit, rollback,
// abort, and each fault window — is provable without a guardian, an HTTP server, or a real
// process. This is what lets a change to the transaction be verified here, not only in the
// e2e chaos run.

/// A scripted stand-in for the live application. `control` and `health` are per-call scripts
/// (the last entry repeats), so a test can make the forward hand-off fail while the rollback
/// succeeds, etc.
struct FakeTower {
    activate: Vec<bool>,
    health: Vec<bool>,
    version_proof: bool,
    activate_i: usize,
    health_i: std::cell::Cell<usize>,
    before_swaps: usize,
    quiesces: usize,
}

impl FakeTower {
    /// Everything succeeds: activation and every health probe.
    fn healthy() -> Self {
        FakeTower {
            activate: vec![true],
            health: vec![true],
            version_proof: false,
            activate_i: 0,
            health_i: std::cell::Cell::new(0),
            before_swaps: 0,
            quiesces: 0,
        }
    }
    fn health_script(mut self, script: Vec<bool>) -> Self {
        self.health = script;
        self
    }
    fn activate_script(mut self, script: Vec<bool>) -> Self {
        self.activate = script;
        self
    }
}

/// Read `script[i]`, repeating the last entry once the script is exhausted (default `true`).
fn scripted(script: &[bool], i: usize) -> bool {
    *script.get(i).or_else(|| script.last()).unwrap_or(&true)
}

impl Control for FakeTower {
    fn before_swap(&mut self) {
        self.before_swaps += 1;
    }
    fn activate(&mut self) -> io::Result<()> {
        let ok = scripted(&self.activate, self.activate_i);
        self.activate_i += 1;
        if ok {
            Ok(())
        } else {
            Err(io::Error::other("activate failed"))
        }
    }
    fn quiesce(&mut self) {
        self.quiesces += 1;
    }
    fn requires_version_proof(&self) -> bool {
        self.version_proof
    }
}

impl Health for FakeTower {
    async fn became_healthy(&self, _expected_version: Option<&str>) -> bool {
        let i = self.health_i.get();
        self.health_i.set(i + 1);
        scripted(&self.health, i)
    }
}

/// A tiny current-thread runtime so the async transaction can be driven synchronously in a
/// unit test (the fakes never touch the network or the clock).
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

/// A store poised to apply `OLD`(v1.0.0) -> `NEW`(v2.0.0): committed at v1, `NEW` staged.
fn ready_to_apply() -> MemStore {
    let mut store = MemStore::committed("1.0.0", "OLD");
    store.set_staged("NEW");
    store
}

#[test]
fn apply_update_happy_path_commits_pending_and_clears_the_journal() {
    let mut store = ready_to_apply();
    let mut tower = FakeTower::healthy();
    let outcome = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ))
    .unwrap();
    assert!(matches!(outcome, Outcome::Committed));
    let st = store.installed_state().unwrap();
    assert_eq!((st.version.as_str(), st.sha256.as_str()), ("2.0.0", "NEW"));
    assert!(
        st.pending.is_some(),
        "an update over a predecessor is pending"
    );
    assert!(!store.journal_present(), "the spent journal is cleared");
    assert!(
        store.has_rollback(),
        "the rollback image is kept for the pending window"
    );
}

#[test]
fn a_post_commit_journal_clear_failure_still_reports_committed() {
    // Round-3 fix #1: once the state is committed the update is durable; failing to delete the
    // spent journal must yield Committed (recovery removes it), never Err — else the loop's
    // in-memory state desyncs from disk and a second update can start over this unconfirmed one.
    let mut store = ready_to_apply();
    store.faults.clear_journal = true;
    let mut tower = FakeTower::healthy();
    let outcome = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ))
    .unwrap();
    assert!(
        matches!(outcome, Outcome::Committed),
        "committed despite the journal-clear fault"
    );
    assert_eq!(store.installed_state().unwrap().version, "2.0.0");
    assert!(
        store.journal_present(),
        "the journal survives the failed clear, for recovery to remove"
    );
}

#[test]
fn a_swap_failure_aborts_leaving_the_binary_untouched() {
    let mut store = ready_to_apply();
    store.faults.swap = true;
    let mut tower = FakeTower::healthy(); // the rollback's health check passes
    let outcome = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ))
    .unwrap();
    assert!(matches!(outcome, Outcome::Aborted));
    assert_eq!(
        store.binary_sha().as_deref(),
        Some("OLD"),
        "the binary was never swapped"
    );
    assert_eq!(store.installed_state().unwrap().version, "1.0.0");
    assert!(!store.journal_present(), "the rollback cleared the journal");
}

#[test]
fn an_unhealthy_update_rolls_back_to_the_predecessor() {
    let mut store = ready_to_apply();
    // The forward health check fails; the rollback's health check passes.
    let mut tower = FakeTower::healthy().health_script(vec![false, true]);
    let outcome = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ))
    .unwrap();
    assert!(matches!(outcome, Outcome::RolledBack));
    assert_eq!(
        store.binary_sha().as_deref(),
        Some("OLD"),
        "reverted to the predecessor bytes"
    );
    assert_eq!(store.installed_state().unwrap().version, "1.0.0");
    assert_eq!(tower.quiesces, 0, "a healthy rollback does not quiesce");
}

#[test]
fn a_failed_activation_rolls_back() {
    let mut store = ready_to_apply();
    // Activation fails on the forward hand-off, then succeeds for the rollback.
    let mut tower = FakeTower::healthy().activate_script(vec![false, true]);
    let outcome = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ))
    .unwrap();
    assert!(matches!(outcome, Outcome::RolledBack));
    assert_eq!(store.binary_sha().as_deref(), Some("OLD"));
    assert_eq!(store.installed_state().unwrap().version, "1.0.0");
}

#[test]
fn a_commit_failure_is_a_transaction_error_that_leaves_the_journal() {
    // The commit is the point of no return; if it fails the update is not durable. apply_update
    // returns Err and leaves the journal so recovery reconciles the swap back.
    let mut store = ready_to_apply();
    store.faults.commit = true;
    let mut tower = FakeTower::healthy();
    let result = block_on(apply_update(
        &mut tower,
        &mut store,
        "NEW",
        "2.0.0",
        Some("1.0.0"),
    ));
    assert!(
        result.is_err(),
        "a commit failure surfaces as a transaction error"
    );
    assert!(
        store.journal_present(),
        "the journal survives for recovery to reconcile"
    );
    assert_eq!(
        store.installed_state().unwrap().version,
        "1.0.0",
        "the commit did not land"
    );
}

#[test]
fn a_first_install_commits_without_pending_and_drops_the_rollback() {
    let mut store = ready_to_apply();
    let mut tower = FakeTower::healthy();
    // from_version = None ⇒ a first install: no predecessor to revert to.
    let outcome = block_on(apply_update(&mut tower, &mut store, "NEW", "1.0.0", None)).unwrap();
    assert!(matches!(outcome, Outcome::Committed));
    assert!(
        store.installed_state().unwrap().pending.is_none(),
        "no predecessor ⇒ no pending intent"
    );
    assert!(
        !store.has_rollback(),
        "a first install drops the rollback copy"
    );
}

#[test]
fn a_failed_confirm_keeps_the_rollback_image_and_pending() {
    // If clearing the pending intent can't be made durable, the rollback image must be kept:
    // while disk still records the update as pending, a crash must still revert to a real
    // binary (the same discipline the boot executor uses).
    let mut store = MemStore::committed("2.0.0", "NEW");
    store.set_binary("NEW");
    store.set_rollback("OLD");
    store
        .commit_installed(&InstalledState {
            version: "2.0.0".into(),
            sha256: "NEW".into(),
            pending: Some(Pending {
                previous_version: "1.0.0".into(),
                previous_sha256: "OLD".into(),
                committed_at: 0,
            }),
        })
        .unwrap();
    store.faults.commit = true;
    assert!(
        !confirm_update(&mut store),
        "the loop must keep its in-memory pending intent after a failed commit"
    );
    assert!(
        store.has_rollback(),
        "a confirm whose commit failed must not drop the rollback image"
    );
    assert!(
        store.installed_state().unwrap().pending.is_some(),
        "the pending intent survives a failed confirm"
    );
}

#[test]
fn restart_mode_names_are_stable() {
    assert_eq!(Restart::StopStart.name(), "stop-start");
    assert_eq!(
        Restart::Reload {
            command: "reexec".into()
        }
        .name(),
        "reload-command"
    );
}

#[cfg(unix)]
#[test]
fn run_reload_maps_the_command_exit_status_to_success_or_error() {
    // The zero-downtime reload succeeds only if the operator command signalling the app to
    // re-exec exits cleanly; a nonzero exit is a failed reload (→ rollback).
    use std::path::Path;
    assert!(run_reload("exit 0", Path::new("/app"), 1).is_ok());
    assert!(
        run_reload("exit 7", Path::new("/app"), 1).is_err(),
        "a nonzero reload-command exit is an error"
    );
}

// ================================= full fuzzing =================================
//
// A seeded, deterministic property fuzzer over the two cores where every bug this review
// found lived: the pure boot planner (`plan_boot`) and the durable transaction
// (`apply_update`, over the Store + Control + Health ports). Each runs thousands of random
// inputs and asserts the safety invariants hold — reproducibly (the failing seed is
// printed) and with no new dependency, real process, socket, clock, or filesystem.

/// A tiny deterministic xorshift PRNG — seeded per iteration so a failure is reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Force nonzero (xorshift fixes on 0) and decorrelate adjacent seeds.
        Rng((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn bits(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn boolean(&mut self) -> bool {
        self.bits() & 1 == 0
    }
    /// True with probability 1-in-`n`.
    fn chance(&mut self, n: u64) -> bool {
        self.bits().is_multiple_of(n)
    }
    fn upto(&mut self, n: u64) -> u64 {
        self.bits() % n
    }
    fn pick(&mut self, xs: &[&'static str]) -> String {
        xs[(self.bits() as usize) % xs.len()].to_string()
    }
    /// A 1-3 element script of outcomes (the last repeats once exhausted).
    fn script(&mut self) -> Vec<bool> {
        let len = 1 + self.upto(3);
        (0..len).map(|_| self.boolean()).collect()
    }
}

const SHAS: &[&str] = &["OLD", "NEW", "OTHER"];
const VERS: &[&str] = &["1.0.0", "2.0.0", "3.0.0"];

fn gen_situation(rng: &mut Rng) -> Situation {
    let installed = match rng.upto(4) {
        0 => Installed::Missing,
        1 => Installed::Invalid,
        _ => {
            let pending = rng.boolean().then(|| Pending {
                previous_version: rng.pick(VERS),
                previous_sha256: rng.pick(SHAS),
                committed_at: rng.upto(2_000_000),
            });
            Installed::Present(InstalledState {
                version: rng.pick(VERS),
                sha256: rng.pick(SHAS),
                pending,
            })
        }
    };
    let journal = rng.boolean().then(|| Transaction {
        old_sha256: rng.pick(SHAS),
        new_sha256: rng.pick(SHAS),
        to_version: rng.pick(VERS),
        from_version: rng.boolean().then(|| rng.pick(VERS)),
    });
    Situation {
        installed,
        baseline: rng
            .boolean()
            .then(|| InstalledState::confirmed(rng.pick(VERS), rng.pick(SHAS))),
        disk_sha: rng.boolean().then(|| rng.pick(SHAS)),
        old_sha: rng.boolean().then(|| rng.pick(SHAS)),
        journal,
        app_crashed: rng.boolean(),
        app_running: rng.boolean().then(|| 1000 + rng.upto(50) as u32),
        bad_supervisor: rng
            .boolean()
            .then(|| std::path::PathBuf::from("/state/supervisors/deadbeef/supervisor")),
        confirm_window: Duration::from_secs(rng.upto(240)),
        now: 1_000_000 + rng.upto(1_000_000),
    }
}

#[test]
fn fuzz_plan_boot_upholds_its_safety_invariants() {
    for seed in 0..20_000 {
        let mut rng = Rng::new(seed);
        let s = gen_situation(&mut rng);
        let plan = plan_boot(&s); // must never panic on any gathered situation

        // Fail-closed is mandatory for unrunnable state.
        if matches!(s.installed, Installed::Invalid) {
            assert!(
                plan.fail_closed.is_some(),
                "seed {seed}: invalid state must fail closed"
            );
        }
        if matches!(s.installed, Installed::Missing) && s.baseline.is_none() {
            assert!(
                plan.fail_closed.is_some(),
                "seed {seed}: missing state with no baseline must fail closed"
            );
        }
        // A journal is only ever cleared when one was present to reconcile.
        if plan.clear_journal {
            assert!(
                s.journal.is_some(),
                "seed {seed}: clear_journal only with a journal"
            );
        }

        if plan.fail_closed.is_some() {
            continue; // fail-closed short-circuits; no other field is acted on.
        }

        // Past fail-closed, a rejected candidate supervisor is exactly the flagged one.
        assert_eq!(
            plan.reject_supervisor, s.bad_supervisor,
            "seed {seed}: reject_supervisor mirrors the input marker"
        );
        // A runnable plan always names the version it is on.
        assert!(
            plan.current.is_some(),
            "seed {seed}: a runnable plan names a current version"
        );
        // Adoption is only of the actually-running pid, and never of an app being quiesced.
        if let Acquire::Adopt(pid) = plan.acquire {
            assert_eq!(
                s.app_running,
                Some(pid),
                "seed {seed}: adopt only the running pid"
            );
            assert!(!plan.quiesce, "seed {seed}: never adopt a quiesced app");
        }
        if plan.quiesce {
            assert_eq!(
                plan.acquire,
                Acquire::Launch,
                "seed {seed}: quiesced ⇒ relaunch, not adopt"
            );
        }
        // A boot commit is always a confirmation/revert — it never re-introduces a pending.
        if let Some(st) = &plan.commit {
            assert!(
                st.pending.is_none(),
                "seed {seed}: a boot commit never re-arms pending"
            );
        }
    }
}

#[test]
fn fuzz_apply_update_always_converges_to_a_consistent_state() {
    // The crash-safety property: for ANY combination of durable faults and control/health
    // outcomes, the transaction followed by recovery leaves the live binary matching the
    // committed state — never a torn "installed says X, binary is Y" split.
    for seed in 0..20_000 {
        let mut rng = Rng::new(seed ^ 0x00C0_FFEE);
        let mut store = MemStore::committed("1.0.0", "OLD");
        store.set_staged("NEW");
        store.faults.write_journal = rng.chance(5);
        store.faults.swap = rng.chance(4);
        store.faults.commit = rng.chance(4);
        store.faults.restore = rng.chance(4);
        store.faults.clear_journal = rng.chance(4);

        let mut tower = FakeTower::healthy();
        tower.activate = rng.script();
        tower.health = rng.script();
        tower.version_proof = rng.boolean();
        let from = rng.boolean().then_some("1.0.0");

        // Drive the transaction (must never panic).
        let _ = block_on(apply_update(&mut tower, &mut store, "NEW", "2.0.0", from));

        // Recovery is retried across "reboots" until it succeeds — the injected faults are
        // one-shot, so a fault that fires during recovery is cleared for the next attempt.
        for _ in 0..8 {
            if recover_through_boot(&mut store).is_ok() {
                break;
            }
        }

        // Invariant: the running binary and the committed state agree.
        if let (Some(bin), Some(st)) = (store.binary_sha(), store.installed_state()) {
            assert_eq!(
                bin, st.sha256,
                "seed {seed}: binary {bin} disagrees with committed {} after recovery",
                st.sha256
            );
        }
        // Invariant: recovery leaves no journal behind (the transaction is fully resolved).
        assert!(
            !store.journal_present(),
            "seed {seed}: a journal survived recovery"
        );
    }
}
