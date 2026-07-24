//! Update policy, transactions, health checks, and rollback for an application owned
//! by the permanent bootstrap guardian. The supervisor is itself replaceable.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use updated::config::{with_suffix, Application, Paths, Repository, Routing, Storage, Timeouts};
use updated::env;
mod app;
mod boot;
mod domain;
mod guardian;
mod install;
mod options;
mod schedule;
mod secrets;
mod selection;
mod self_update;
mod store;
mod telemetry;
mod update;

use app::*;
use boot::plan_boot;
use domain::*;
use guardian::Guardian;
use install::ensure_installed;
use options::*;
use schedule::*;
use selection::*;
use self_update::*;
use store::*;
use update::*;

use updated::hash::{sha256_file, verify_file};
use updated_tuf::select::{target_sha, SelectedRelease};
use updated_tuf::{DefaultPolicy, TrustedRepository};

/// This supervisor build's version, baked in (see `build.rs`). Self-update selection is
/// by content hash, not this — it is for logs and for distinguishing builds.
const SELF_VERSION: &str = env!("SUPERVISOR_VERSION");

struct Options {
    deployment: String,
    routing: Routing,
    repository: Repository,
    application: Application,
    timeouts: Timeouts,
    storage: Storage,
    /// Canonical bundle installation layout.
    paths: Paths,
    supervisor_update: SupervisorUpdate,
    secrets: secrets::SecretManager,
}

impl Options {
    /// Reconcile the managed runtime against the live assignment resolved this cycle. The
    /// runtime (launch args, health checks, cadence, retention) is signed into the SAME
    /// assignment that carries the version and provider set, so a control-plane reassignment
    /// can change it with no version bump. The version/provider are reconciled by
    /// `check_application`; this reconciles everything else onto the one live source.
    ///
    /// Returns whether the *launch spec* changed — an app running the old args must be
    /// relaunched to pick up the new ones, since a live process's argv cannot be rewritten in
    /// place.
    fn apply_runtime(&mut self, runtime: &updated::config::ManagedRuntime) -> bool {
        let relaunch = self.application.args != runtime.args
            || self.application.mode != runtime.mode
            || self.application.secrets != runtime.secrets;
        self.application = runtime.application();
        self.timeouts = runtime.timeouts();
        self.storage = runtime.storage();
        relaunch
    }
}

/// The supervisor stages a verified release from the reserved `supervisor` product
/// into the guardian's content-addressed state directory and hands it off for a
/// readiness-gated replacement.
struct SupervisorUpdate {
    channel: String,
    /// The guardian's state directory, holding `supervisors/<id>/` staging dirs.
    state_dir: PathBuf,
    check_interval: Duration,
}

/// Mutable bookkeeping for the update-check loop. The supervisor no longer restarts or
/// watches the application (the guardian does), so this is just the metadata-refresh
/// backoff and the next application-update deadline.
struct LoopState {
    refresh_failures: u32,
    next_app_check: Instant,
}

impl LoopState {
    fn new(check_interval: Duration) -> Self {
        Self {
            refresh_failures: 0,
            next_app_check: Instant::now() + jitter(check_interval, 20),
        }
    }
}

fn main() {
    // The chaos-feature build can enumerate its own transaction boundaries, so the e2e
    // drives exactly the crossings the supervisor defines instead of a hand-copied list.
    #[cfg(feature = "chaos")]
    if let Some(kind) = std::env::args().find(|a| {
        a == "--list-chaos-boundaries"
            || a == "--list-rollback-chaos-boundaries"
            || a == "--list-abort-chaos-boundaries"
            || a == "--list-install-chaos-boundaries"
    }) {
        let boundaries = match kind.as_str() {
            "--list-chaos-boundaries" => update::BOUNDARIES,
            "--list-rollback-chaos-boundaries" => update::ROLLBACK_BOUNDARIES,
            "--list-install-chaos-boundaries" => install::INSTALL_BOUNDARIES,
            _ => update::ABORT_BOUNDARIES,
        };
        for b in boundaries {
            println!("{b}");
        }
        return;
    }

    // reqwest is built without a default TLS provider so the TUF client and
    // health probe share the workspace's single aws-lc-rs implementation.
    updated::tls::install_crypto_provider();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let opts = match runtime.block_on(parse_args()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("supervisor: {e}\n");
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = runtime.block_on(run(opts)) {
        eprintln!("supervisor: fatal: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!("usage: supervisor --config <bootstrap.toml>");
    eprintln!("the bootstrap file contains the node name, enrollment URL, CA, and shared fleet cert paths");
}

async fn run(mut opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    // One owner protects the shared binary, state, journal, and staging paths.
    let _lock = updated::lock::InstanceLock::acquire(&with_suffix(&opts.paths.state, ".lock"))
        .map_err(|e| format!("another supervisor already owns this install: {e}"))?;

    // Watch for a stop/restart signal; when it fires the supervisor exits. It does NOT
    // touch the application: the guardian is the service's main process and stops the
    // app itself on a clean stop.
    let shutdown = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_shutdown_signal().await;
            shutdown.store(true, Ordering::SeqCst);
        }
    });

    let mut guardian =
        Guardian::connect().map_err(|e| format!("connecting to the guardian: {e}"))?;
    let guardian_state = guardian::state_dir();

    let mut store = FileStore::open(opts.paths.clone())?;

    // Reconcile any in-flight install journal and cold-install a fresh node, returning whether
    // this boot performed the install. That selects the pre-start hook's reason (install vs.
    // restart) so an operator script can seed on first boot and merely clean up on later
    // restarts. All first-install placement — including Custom's provider hook — happens inside
    // this durable, crash-recoverable install; there is no first-install branch after it.
    let first_install = ensure_installed(&opts, &mut store).await?;

    // The disk is not trusted merely because it was verified during installation. This
    // check is local and deliberately precedes every repository access. A modified
    // committed bundle is never launched, even when the network is unavailable.
    if let updated::state::Installed::Present(installed) = store.installed() {
        if let Err(error) =
            updated::bundle::verify_release(&opts.paths.versions, &installed.release)
        {
            let _ = guardian.stop();
            repair_from_local_assignment(&opts, &mut store)
                .await
                .map_err(|repair| {
                    format!(
                        "committed application bundle failed local verification ({error}); no valid signed local repair was applicable: {repair}"
                    )
                })?;
        }
    }

    // Gather the whole world into a Situation and let the pure boot planner decide
    // everything: recovery, drift enforcement, crash rejection, pending confirm/revert,
    // and whether to adopt the running application or launch a fresh one.
    let situation = gather_situation(&opts, &store, guardian_state.as_deref(), first_install)?;
    let mut recovery_transaction = recovery_transaction(&situation);
    // A *provisional* committed head (`confirmed == false`, never health-proven) that crashed (the
    // guardian recorded a service exit) with no pending update to revert is a broken assigned head
    // that a first-install cold-installed. Reject its bytes and restart *before* relaunching
    // it: the next boot's cold install descends via ordered fallback to the newest healthy release.
    // A confirmed head that crashes transiently is a no-op here, so it falls through to the normal
    // relaunch-and-recover path — the single-crash recovery the base e2e relies on.
    //
    // The `!first_install` guard is load-bearing: when *this* boot descended and (re)installed a
    // new head, that head has not launched yet, so a `service_exited` marker on disk is the stale
    // exit of the *previous* head (which is exactly what drove this descent). Acting on it here
    // would reject the freshly-installed release before it ever runs — stranding a cold node on an
    // exhausted descent even though a healthy release was available (the fleet baseline-rejection
    // bug). A genuine crash of *this* head is caught on the next boot (no longer first_install) or,
    // if it fails its gate this boot, by the boot health gate below.
    if situation.service_exited && recovery_transaction.is_none() && !situation.first_install {
        if let Installed::Present(state) = &situation.installed {
            if reject_provisional_head(&mut store, state, "crashed with no pending update")? {
                return Err("provisional head crashed; descending on the next boot".into());
            }
        }
    }
    let defer_recovery_commit = recovery_transaction
        .as_ref()
        .is_some_and(Transaction::is_rollback);
    let plan = plan_boot(&situation);
    for note in &plan.notes {
        match note.level {
            Level::Info => log(&note.msg),
            Level::Warn => warn(&note.msg),
        }
    }
    if let Some(reason) = &plan.fail_closed {
        error(reason);
        return Err(reason.clone().into());
    }
    let updates_enabled = plan.updates_enabled;
    let mut current = plan.current.clone();

    let mut self_update = SelfUpdateState::load(&opts)?;

    // A confirmation-window crash starts rollback by materializing the same phase journal
    // used by ordinary activation failures. From this write onward there is exactly one
    // recovery path, including if this supervisor dies before touching the pointer.
    if defer_recovery_commit && situation.journal.is_none() {
        persist_transaction(
            &mut store,
            recovery_transaction
                .as_ref()
                .expect("pending lifecycle recovery has a transaction"),
        )?;
    }
    if let Some(tx) = recovery_transaction.as_mut() {
        if !tx.is_rollback() {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackStarted)?;
        }
    }

    // Perform the plan's durable reconciliation (binary, rejections, commit), yielding the
    // still-unconfirmed update (if any) for the loop to confirm once its window passes.
    let mut pending = match execute_boot_plan(
        &plan,
        &opts,
        &mut store,
        &mut guardian,
        &mut self_update,
        defer_recovery_commit,
        recovery_transaction.as_mut(),
    ) {
        Ok(pending) => pending,
        Err(error) => {
            return hold_recovery_after_provider_failure(
                &shutdown,
                format!("boot/update recovery hook failed: {error}"),
            )
            .await;
        }
    };
    // Restore the predecessor's activation before relaunching it (rollback recovery). A restart
    // deployment has no live process here (it was stopped); a reload deployment kept it and reloads
    // it in place — `complete_recovery_activation` resolves that itself.
    if let Err(error) =
        complete_recovery_activation(&opts, &mut store, recovery_transaction.as_mut())
    {
        return hold_recovery_after_provider_failure(
            &shutdown,
            format!("predecessor activation recovery hook failed: {error}"),
        )
        .await;
    }
    if let Some(tx) = recovery_transaction.as_mut() {
        if tx.rollback_rank().is_some_and(|rank| rank < 5) {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackStartStarted)?;
        }
    }
    if pending.is_some() {
        if let Some(v) = current.as_deref() {
            log(&format!(
                "update {v} is unconfirmed; a crash within its window reverts it"
            ));
        }
    }

    log(&format!(
        "supervisor {SELF_VERSION} (default provider {}) supervising {:?} (product {} channel {}, installed {}, updates {}, check every {}s)",
        DefaultProvider::VERSION,
        opts.paths.install_root,
        opts.application.product,
        opts.application.channel,
        current.as_deref().unwrap_or("none"),
        if updates_enabled { "enabled" } else { "DISABLED" },
        opts.timeouts.check_interval.as_secs()
    ));

    let mut app = match plan.acquire {
        Acquire::Adopt(pid) => adopt(guardian, &opts, pid)?,
        // Pre-start is a clean-boot environment hook. A boot that is resuming an interrupted
        // update or rollback (recovery_transaction is Some) must replay only that
        // transaction's minimal, idempotent steps — injecting a fresh per-boot hook there
        // would run the operator provider outside the transaction. So pre-start fires only on
        // an ordinary launch, never on a recovery relaunch.
        Acquire::Launch => launch_with_pre_start(
            guardian,
            &opts,
            &store,
            if recovery_transaction.is_some() {
                None
            } else if first_install {
                Some(LifecycleReason::Install)
            } else {
                Some(LifecycleReason::Restart)
            },
        )?,
    };
    if recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.rollback_rank().is_some_and(|rank| rank < 6))
    {
        let tx = recovery_transaction.as_ref().expect("checked above");
        if let Err(error) = invoke_deployment_provider(
            tx.lifecycle.as_ref(),
            &opts,
            LifecycleInvocation {
                phase: LifecyclePhase::Start,
                reason: LifecycleReason::Update,
                id: &tx.id,
                pid: app.pid(),
                candidate: &tx.previous_release,
                predecessor: &tx.candidate_release,
            },
        ) {
            return hold_recovery_after_provider_failure(
                &shutdown,
                format!("predecessor start recovery hook failed: {error}"),
            )
            .await;
        }
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_START_APPLIED);
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::PredecessorStarted)?;
    }

    if let Some(tx) = recovery_transaction.as_mut() {
        if tx.rollback_rank().is_some_and(|rank| rank < 7) {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackHealthStarted)?;
        }
    }
    // Signal *supervisor* readiness to the guardian now that this process is up and owns a running
    // application — BEFORE the app health gate below. For a committed supervisor this is a no-op;
    // for a candidate it begins the guardian's confirmation window. Signalling here (not after the
    // app health gate) decouples "the supervisor process started successfully" from "the app is
    // healthy": a slow-to-start app during a swap can no longer blow the guardian's ready_timeout
    // and get a perfectly good supervisor permanently rejected. If the app then fails its gate the
    // supervisor exits, which the guardian sees as a candidate dying in its window and rejects —
    // so a supervisor whose app cannot get healthy is still not committed.
    if let Err(e) = app.signal_ready() {
        warn(&format!("could not signal readiness to the guardian: {e}"));
    }
    #[cfg(all(feature = "chaos", supervisor_chaos_exit_after_ready))]
    {
        eprintln!("supervisor: CHAOS: exiting after readiness, before guardian confirmation");
        std::process::exit(137);
    }
    // Gate readiness: the application must be healthy before we trust this boot. A crash
    // would have torn the tower down instead, so an unhealthy result here means the
    // process is alive but wedged — fail closed. For a candidate supervisor, failing this
    // exits before signalling ready, so the guardian rolls the candidate back. The lifecycle
    // provider's verify phase is the application-specific signal.
    // During a crash-recovered rollback the predecessor commit is deferred until *after* this gate,
    // so `store.installed()` still holds the CANDIDATE record. Gate the restored predecessor with
    // ITS OWN lifecycle provider — carried in the recovery transaction from `pending` (the
    // operator set staged for exactly this rollback) — not the candidate's. Otherwise an update that
    // revised the lifecycle provider, then failed, would gate the healthy predecessor with the
    // candidate's policy, reject it, and crash-loop a good release.
    let installed_state = match store.installed() {
        Installed::Present(installed) => installed,
        _ => return Err("cannot verify a boot without an installed release".into()),
    };
    let installed = installed_state.release.clone();
    let installed_lifecycle = match recovery_transaction.as_ref() {
        Some(tx) if tx.is_rollback() => tx.lifecycle.clone(),
        _ => installed_state.lifecycle,
    };
    let mut tower = DefaultProvider::new(&mut app, &opts, installed_lifecycle.as_ref());
    let boot_healthy = update::became_verified(&mut tower, "boot", &installed, &installed).await;
    if !boot_healthy {
        // A crash-recovered rollback whose restored predecessor cannot pass the gate is the
        // dangerous case: `reject_provisional_head` below would no-op (the still-deferred
        // `store.installed()` holds the CONFIRMED candidate, not the predecessor), so without a
        // bound the guardian relaunches, the journal re-derives the identical rollback, and it runs
        // forever with the node down. Bound it: count failures durably in the journal (which is what
        // survives the relaunch) and, once the limit is hit, reject the predecessor's bytes and
        // descend via the same ordered-fallback path a cold install uses.
        if let Some(tx) = recovery_transaction.as_mut().filter(|tx| tx.is_rollback()) {
            let predecessor = tx.previous_release.version.clone();
            match bound_unhealthy_rollback(&mut store, tx) {
                Ok(RollbackHealthOutcome::Descend) => error(&format!(
                    "rollback target {predecessor} is unhealthy after {MAX_ROLLBACK_HEALTH_ATTEMPTS} \
                     attempts; rejected its bytes and cleared the rollback so the next boot descends \
                     via ordered fallback past it"
                )),
                Ok(RollbackHealthOutcome::Retry(attempt)) => warn(&format!(
                    "rollback target {predecessor} unhealthy (attempt {attempt} of \
                     {MAX_ROLLBACK_HEALTH_ATTEMPTS}); retrying the same predecessor on the next boot"
                )),
                Err(error) => warn(&format!(
                    "recording the unhealthy rollback target failed: {error}"
                )),
            }
            app.guardian
                .application_failed()
                .map_err(|error| format!("reporting rollback-target health failure: {error}"))?;
            return Err("the rollback target failed its health gate".into());
        }
        // A still-provisional head that never becomes healthy is a broken assigned head wedged
        // alive (a crash instead tears the tower down before here — see the service-exit path at
        // boot gather). Reject its bytes so the next boot's cold install descends via ordered
        // fallback to the newest healthy release rather than relaunching a head that can't serve.
        // A confirmed head that fails is a no-op here and left alone for the normal path.
        if let updated::state::Installed::Present(state) = store.installed() {
            if let Err(error) =
                reject_provisional_head(&mut store, &state, "wedged alive without a passing gate")
            {
                warn(&format!(
                    "recording rejection of the failed provisional head failed: {error}"
                ));
            }
        }
        app.guardian
            .application_failed()
            .map_err(|error| format!("reporting initial application health failure: {error}"))?;
        return Err("the managed application failed its initial health check".into());
    }
    // The head has now proven healthy this boot: confirm it so a later transient crash of this
    // (proven) head is relaunched and recovered, not rejected as a broken head.
    if let updated::state::Installed::Present(mut state) = store.installed() {
        if state.confirm() {
            if let Err(error) = store.commit_installed(&state) {
                warn(&format!("confirming the proven head failed: {error}"));
            }
        }
    }
    if recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.rollback_rank().is_some_and(|rank| rank < 8))
    {
        let tx = recovery_transaction.as_ref().expect("checked above");
        if let Err(error) = invoke_deployment_provider(
            tx.lifecycle.as_ref(),
            &opts,
            LifecycleInvocation {
                phase: LifecyclePhase::Verify,
                reason: LifecycleReason::Update,
                id: &tx.id,
                pid: app.pid(),
                candidate: &tx.previous_release,
                predecessor: &tx.candidate_release,
            },
        ) {
            return hold_recovery_after_provider_failure(
                &shutdown,
                format!("predecessor verify recovery hook failed: {error}"),
            )
            .await;
        }
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_HEALTH_APPLIED);
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::PredecessorHealthy)?;
    }

    // A crash may have interrupted the operator's drain/prepare/finalize work. Once the
    // predecessor is healthy again, replay the idempotent rollback phase with the same
    // transaction identity before declaring the recovered tower ready.
    let rollback_incomplete = recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.rollback_rank().is_some_and(|rank| rank < 10));
    if rollback_incomplete {
        if let Some(tx) = recovery_transaction.as_mut() {
            if tx.rollback_rank().is_some_and(|rank| rank < 9) {
                advance_transaction(&mut store, tx, TransactionPhase::RollbackFinalizeStarted)?;
            }
        }
        if let (Some(tx), Some(lifecycle)) = (
            recovery_transaction.as_ref(),
            recovery_transaction
                .as_ref()
                .map(|tx| tx.lifecycle.as_ref()),
        ) {
            if let Err(error) = run_lifecycle_command(
                lifecycle,
                &opts,
                LifecycleInvocation {
                    phase: LifecyclePhase::Rollback,
                    reason: LifecycleReason::Update,
                    id: &tx.id,
                    pid: app.pid(),
                    candidate: &tx.previous_release,
                    predecessor: &tx.candidate_release,
                },
            ) {
                return hold_recovery_after_provider_failure(
                    &shutdown,
                    format!("rollback recovery hook failed: {error}"),
                )
                .await;
            }
            Chaos::from_env().crossing(update::boundary::ROLLBACK_ADAPTER_APPLIED);
        }
    }
    if rollback_incomplete {
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::RolledBack)?;
    }
    if defer_recovery_commit {
        if let Some(state) = &plan.commit {
            store.commit_installed(state)?;
            pending = installed_pending(&store);
        }
    }
    // Keep the journal until both release reconciliation and any environmental rollback
    // have succeeded. If either the wrapper or this supervisor dies, the next boot sees
    // the same evidence and repeats the idempotent recovery instead of declaring success.
    if plan.clear_journal || defer_recovery_commit {
        store.clear_journal()?;
    }
    garbage_collect(&opts, &store);

    // Publish application readiness (traffic rotation) only now that the app has passed its health
    // gate — never route traffic to an app that has not proven healthy. This is distinct from the
    // guardian *supervisor*-readiness signalled earlier: this one is about the app, that one about
    // this process being a working supervisor.
    app.traffic_ready(true)
        .map_err(|error| format!("publishing initial application readiness: {error}"))?;

    let mut loop_state = LoopState::new(opts.timeouts.check_interval);
    // The installed lifecycle provider's periodic phase is the steady-state signal. It drives
    // readiness and liveness and is refreshed when an update commits.
    let mut steady_lifecycle = installed_lifecycle_provider(&store)?;
    let mut next_health_probe = Instant::now() + opts.timeouts.health_interval;
    let mut liveness_failures = 0u32;
    // Rollout telemetry: this node's identity and a client for best-effort reports. Both
    // are inert unless the current assignment carries a report URL; a node without a
    // derivable identity or a failing client simply never reports and updates as usual.
    //
    // The report endpoint is the fleet gateway, which admits only fleet-CA client certs — the
    // same mTLS the node already uses to fetch its repository — so the telemetry client presents
    // the node's identity. If that identity can't build (an offline/non-mTLS deployment with no
    // CA on disk), fall back to a plain client: telemetry is best-effort, and a plain-HTTP report
    // target is served as usual.
    let telemetry_node = telemetry::node_identity(&opts.routing);
    let telemetry_client = opts
        .routing
        .mtls
        .reqwest_client()
        .unwrap_or_else(|_| reqwest::Client::new());
    // The node signs each report with the SAME per-node key that certifies its mTLS leaf, so the
    // control plane verifies authenticity end-to-end (not just on the write hop). Loaded once as
    // PKCS#8 DER; absent only for a mis-provisioned node, whose unsigned reports then fail closed at
    // the throttle (treated as not-yet-settled) rather than being trusted.
    let telemetry_signing_key = std::fs::read_to_string(&opts.routing.mtls.client_key)
        .ok()
        .and_then(|pem| updated::csr::key_pem_to_pkcs8_der(&pem).ok());
    // Latest readiness observation, so a report reflects whether the running deployment is
    // actually serving. `None` until first sampled (or when no readiness check exists).
    let mut last_ready: Option<bool> = None;
    loop {
        // An unconfirmed update that ran its whole window without crashing is confirmed.
        let confirm_due = pending
            .as_ref()
            .is_some_and(|p| window_passed(p, opts.timeouts.confirmation_window, now_unix()));
        let mut confirm_failed = false;
        if confirm_due {
            if confirm_update(&mut store) {
                pending = None;
                log(&format!(
                    "update {} confirmed; confirmation window passed",
                    current.as_deref().unwrap_or("?")
                ));
                garbage_collect(&opts, &store);
            } else {
                confirm_failed = true;
            }
        }

        let now = Instant::now();
        // Wake when the confirmation window ends even if the update interval is longer.
        let app_wait = if let Some(p) = pending.as_ref() {
            if confirm_failed {
                // The window has already elapsed, so `window_remaining` is zero and the
                // wait would fall to its 100ms floor: a confirm that cannot be persisted (a
                // full or read-only state dir) would re-attempt — and re-warn — ten times a
                // second for as long as the fault lasts. Retry on the normal cadence.
                opts.timeouts.check_interval
            } else {
                window_remaining(p, opts.timeouts.confirmation_window, now_unix())
            }
        } else if updates_enabled {
            loop_state.next_app_check.saturating_duration_since(now)
        } else {
            opts.timeouts.check_interval
        };
        let mut wait = app_wait.min(self_update.due_in(now));
        wait = wait.min(next_health_probe.saturating_duration_since(now));
        let wait = wait.max(Duration::from_millis(100));

        if sleep_interruptible(wait, &shutdown).await {
            log("shutdown requested; exiting (the guardian stops the application)");
            return Ok(());
        }

        let now = Instant::now();
        if now >= next_health_probe {
            // One periodic hook invocation per tick drives readiness and liveness.
            next_health_probe = now + opts.timeouts.health_interval;
            let installed = match store.installed() {
                Installed::Present(installed) => installed.release,
                _ => return Err("periodic verification has no installed release".into()),
            };
            let healthy = invoke_deployment_provider(
                steady_lifecycle.as_ref(),
                &opts,
                LifecycleInvocation {
                    phase: LifecyclePhase::Periodic,
                    reason: LifecycleReason::Restart,
                    id: "periodic",
                    pid: app.pid(),
                    candidate: &installed,
                    predecessor: &installed,
                },
            )
            .is_ok();
            last_ready = Some(healthy);
            app.traffic_ready(healthy)
                .map_err(|error| format!("publishing application readiness: {error}"))?;
            if healthy {
                liveness_failures = 0;
            } else {
                liveness_failures = liveness_failures.saturating_add(1);
                if liveness_failures >= 3
                    && opts.application.mode == updated::config::RuntimeMode::Managed
                {
                    app.guardian.application_failed().map_err(|error| {
                        format!("reporting application liveness failure: {error}")
                    })?;
                    return Err("the managed application failed its liveness check".into());
                }
            }
        }
        let self_due = self_update.due(now);
        let app_due = application_check_due(
            updates_enabled,
            pending.is_some(),
            now,
            loop_state.next_app_check,
        );
        if !self_due && !app_due {
            continue;
        }

        if let updated::state::Installed::Present(installed) = store.installed() {
            if let Err(error) =
                updated::bundle::verify_release(&opts.paths.versions, &installed.release)
            {
                let _ = app::stop_runtime(&mut app);
                repair_from_local_assignment(&opts, &mut store)
                    .await
                    .map_err(|repair| {
                        format!(
                            "committed application bundle changed on disk ({error}); stopped it before repository access and no valid signed local repair was applicable: {repair}"
                        )
                    })?;
                current = match store.installed() {
                    updated::state::Installed::Present(state) => Some(state.release.version),
                    _ => None,
                };
                pending = None;
                app.launch(&opts)?;
            }
        }

        // Resolve the agent document afresh, then load its release repository.
        // One verified result serves application and self checks this cycle, and a
        // control-plane reassignment therefore takes effect without process restart.
        let repo = match TrustedRepository::assigned(
            &opts.routing,
            &opts.repository,
            &opts.storage,
            &opts.paths,
        )
        .await
        {
            Ok(repo) => repo,
            Err(e) => {
                loop_state.refresh_failures = loop_state.refresh_failures.saturating_add(1);
                let base = if e.is_retryable() {
                    opts.timeouts.refresh_retry
                } else {
                    opts.timeouts.check_interval
                };
                let retry = network_backoff(base, loop_state.refresh_failures);
                match &e {
                updated_tuf::Error::Transport(_) => warn(&format!(
                    "TUF refresh failed ({e}); retrying in {}s",
                    retry.as_secs()
                )),
                updated_tuf::Error::Trust(_) => error(&format!(
                    "TUF refresh failed a trust check ({e}); not updating (fail closed), rechecking in {}s",
                    retry.as_secs()
                )),
                updated_tuf::Error::Local(_) => error(&format!(
                    "TUF refresh failed locally ({e}); not updating, rechecking in {}s",
                    retry.as_secs()
                )),
            }
                loop_state.next_app_check = Instant::now() + jitter(retry, 20);
                self_update.defer(Instant::now() + retry);
                continue;
            }
        };
        loop_state.refresh_failures = 0;

        // Reconcile the managed runtime onto the one live source before acting on version or
        // provider changes. `check_application` reconciles the version and provider set; the
        // rest of the runtime — launch args, health URLs, cadence, retention — is signed into
        // the same assignment and can change on a control-plane reassignment with no version
        // bump. Applying it here keeps every launch on the current launch spec.
        if let Some(assignment) = repo.assignment() {
            let secrets_changed = match opts
                .secrets
                .reconcile(&assignment.deployment, &assignment.runtime.secrets)
                .await
            {
                Ok(changed) => changed,
                Err(error) => {
                    warn(&format!(
                        "assigned secrets could not be reconciled; keeping the running application and retrying: {error}"
                    ));
                    loop_state.next_app_check =
                        Instant::now() + jitter(opts.timeouts.refresh_retry, 20);
                    continue;
                }
            };
            opts.deployment = assignment.deployment.clone();
            let relaunch = opts.apply_runtime(&assignment.runtime) || secrets_changed;
            if relaunch {
                // The launch spec changed. A live process cannot have its argv rewritten, so
                // stop it and relaunch on the new args.
                log("assignment runtime changed the launch spec; relaunching the application to apply it");
                app::stop_runtime(&mut app).map_err(|error| {
                    format!("stopping the application to apply a new launch spec: {error}")
                })?;
                app.launch(&opts).map_err(|error| {
                    format!("relaunching the application with the new launch spec: {error}")
                })?;
                // Re-gate readiness from scratch and let the next tick drive the version/provider
                // reconciliation against the freshly relaunched, correctly-configured process.
                last_ready = None;
                next_health_probe = Instant::now() + opts.timeouts.health_interval;
                loop_state.next_app_check = Instant::now();
                continue;
            }
        }

        // Self-update first: on an accepted handoff this process exits.
        if self_due {
            self_update
                .check(&opts.supervisor_update, &repo, &mut app.guardian)
                .await;
        }

        if app_due {
            loop_state.next_app_check = Instant::now() + jitter(opts.timeouts.check_interval, 20);
            match check_application(&opts, &repo, &mut store, &mut app).await {
                AppOutcome::Upgraded { version } => {
                    current = Some(version);
                    // The commit recorded the update as unconfirmed; pick it up so its
                    // window is watched and a crash is caught on the next boot.
                    pending = installed_pending(&store);
                    // The new release's lifecycle provider travels with it.
                    steady_lifecycle = installed_lifecycle_provider(&store)?;
                    garbage_collect(&opts, &store);
                }
                AppOutcome::Unchanged => {}
                AppOutcome::RestartForRecovery => {
                    // A post-activation failure left a durable rollback journal. Terminate this
                    // disposable supervisor cleanly; the guardian relaunches it and boot recovery
                    // performs the rollback (the single rollback path). The guardian keeps the
                    // application alive across the restart.
                    log("update failed after activation; restarting so boot recovery rolls back");
                    return Ok(());
                }
                AppOutcome::Fatal(message) => {
                    return hold_recovery_after_provider_failure(
                        &shutdown,
                        format!("update transaction requires boot recovery: {message}"),
                    )
                    .await;
                }
            }
        }

        // Best-effort rollout heartbeat, emitted after acting on the current assignment.
        // `healthy` is true only when the running app is ready AND no update is still
        // unconfirmed (`pending`) — so a node that has merely *fetched* a new assignment,
        // or is mid-rollout, is never reported as settled on it. That is exactly what lets
        // the control plane hold a pair's second member until the first has genuinely
        // completed (installed and confirmed, or attempted and rolled back). Keyed off the
        // current assignment's report URL, so adding or removing telemetry just starts or
        // stops the heartbeat.
        if let Some(assignment) = repo.assignment() {
            // Do not report settled until the first steady-state observation has passed.
            let settled = pending.is_none() && last_ready.unwrap_or(false);
            telemetry::report_running_state(
                &telemetry_client,
                assignment.report_url.as_deref(),
                telemetry_node.as_deref(),
                &assignment.deployment,
                current.as_deref().unwrap_or_default(),
                settled,
                telemetry_signing_key.as_deref(),
            )
            .await;
        }
    }
}

/// Repair a damaged committed release from the same signed deployment contract used by
/// normal updates, but only when its routing repository is explicitly local. This path
/// performs no network request and is therefore safe to try before online reconciliation.
async fn repair_from_local_assignment(
    opts: &Options,
    store: &mut FileStore,
) -> Result<(), Box<dyn std::error::Error>> {
    if !opts.routing.is_local() {
        return Err("the signed routing repository is not local".into());
    }
    let repo =
        TrustedRepository::assigned(&opts.routing, &opts.repository, &opts.storage, &opts.paths)
            .await
            .map_err(|error| format!("loading signed local repair assignment: {error}"))?;
    let assignment = repo
        .assignment()
        .ok_or("the signed local repository has no desired deployment")?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    let prepared = update_client::prepare_assigned_application(
        update_client::ApplicationRequest {
            repository: &repo,
            application: &opts.application,
            repository_config: &opts.repository,
            paths: &opts.paths,
            current_version: None,
        },
        |sha256| store.is_rejected(&lineage, sha256),
    )
    .await
    .map_err(|error| format!("preparing signed local repair: {error}"))?
    .ok_or("the signed local assignment contains no installable application")?;
    let providers = selection::stage_providers(opts, &repo, store, None)
        .await
        .map_err(|error| format!("staging the providers for local repair: {error}"))?;
    store.commit_installed(&updated::state::InstalledState::confirmed(
        lineage,
        prepared.release.clone(),
        prepared.archive_sha256,
        Box::new(providers),
    ))?;
    store.activate(&prepared.release)?;
    log(&format!(
        "repaired the committed application from signed local deployment {}",
        prepared.version
    ));
    Ok(())
}

/// A recovery hook is operator code. If it fails, keep the existing application and
/// durable transaction evidence in place, but do not let the guardian repeatedly restart
/// this supervisor and replay the same non-idempotent boundary forever. The process stays
/// alive until the service manager stops it (or the guardian rejects a not-ready candidate).
async fn hold_recovery_after_provider_failure(
    shutdown: &Arc<AtomicBool>,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    error(&format!(
        "{reason}; recovery is held with its journal intact"
    ));
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn garbage_collect(opts: &Options, store: &dyn Store) {
    let Installed::Present(installed) = store.installed() else {
        return;
    };
    let mut releases = vec![installed.release.clone()];
    let mut providers = Vec::new();
    // Protect the installed release's own providers — they run on every boot (pre-start,
    // verification) — and the pending predecessor's, which a rollback would replay.
    providers.push(installed.lifecycle.release);
    if let Some(pending) = installed.pending {
        releases.push(pending.previous_release);
        providers.push(pending.lifecycle.release);
    }
    match updated::gc::prune_releases(
        &opts.paths.versions,
        &releases,
        opts.storage.inactive_releases,
        opts.storage.inactive_bytes,
    ) {
        Ok(removed) if removed != 0 => {
            log(&format!("removed {removed} inactive application releases"))
        }
        Ok(_) => {}
        Err(error) => warn(&format!(
            "garbage collecting application releases failed: {error}"
        )),
    }
    match updated::gc::prune_releases(
        &opts.paths.provider_versions,
        &providers,
        opts.storage.inactive_providers,
        opts.storage.inactive_bytes,
    ) {
        Ok(removed) if removed != 0 => {
            log(&format!("removed {removed} inactive lifecycle providers"))
        }
        Ok(_) => {}
        Err(error) => warn(&format!(
            "garbage collecting lifecycle providers failed: {error}"
        )),
    }
}

/// Reject the bytes of a *provisional* (never-health-proven) cold-installed head so the next
/// boot's cold install descends via ordered fallback past it. A confirmed head is left untouched.
/// Returns whether a rejection was actually recorded (i.e. the head was provisional). This is the
/// single reject rule shared by the two ways a provisional head can prove bad: it crashed last
/// boot (service exit) or it wedged alive through the boot health gate.
fn reject_provisional_head(
    store: &mut FileStore,
    state: &updated::state::InstalledState,
    why: &str,
) -> std::io::Result<bool> {
    if state.confirmed {
        return Ok(false);
    }
    store.reject(&state.repository_lineage, &state.archive_sha256)?;
    warn(&format!(
        "provisional head {} {why}; rejected its bytes so the next cold install descends via \
         ordered fallback",
        state.release.version
    ));
    Ok(true)
}

/// How many consecutive boots may fail to health-gate a crash-recovered rollback's predecessor
/// before the supervisor stops retrying it and descends via ordered fallback. More than one so a
/// merely slow-to-start predecessor is not abandoned on its first miss; small so a genuinely broken
/// predecessor cannot keep the node down for long.
const MAX_ROLLBACK_HEALTH_ATTEMPTS: u32 = 3;

/// What a boot does after a crash-recovered rollback's predecessor fails its health gate.
#[derive(Debug, PartialEq, Eq)]
enum RollbackHealthOutcome {
    /// Still under the bound: the incremented counter is persisted and the same predecessor is
    /// retried on the next boot. Carries the attempt number for the log.
    Retry(u32),
    /// The bound was reached: the predecessor's bytes are rejected, it is recorded as a provisional
    /// (now-rejected) head, and the rollback journal is cleared, so the next boot's
    /// [`ensure_installed`] descends via ordered fallback past it exactly as a cold install does.
    Descend,
}

/// Bound rollback-target health failures so a predecessor whose bytes can no longer pass the gate
/// cannot crash-loop the node forever. The failure count rides the journal (the very thing that
/// re-derives the rollback on each boot, so it survives the guardian relaunch). Once it reaches
/// [`MAX_ROLLBACK_HEALTH_ATTEMPTS`], this rejects the predecessor, records it provisional, and drops
/// the journal — the next boot then descends via the cold-install ordered-fallback path instead of
/// relaunching the same broken predecessor.
fn bound_unhealthy_rollback(
    store: &mut dyn Store,
    tx: &mut Transaction,
) -> io::Result<RollbackHealthOutcome> {
    tx.rollback_health_failures = tx.rollback_health_failures.saturating_add(1);
    if tx.rollback_health_failures >= MAX_ROLLBACK_HEALTH_ATTEMPTS {
        store.reject(&tx.previous_repository_lineage, &tx.previous_archive_sha256)?;
        store.commit_installed(&updated::state::InstalledState::provisional(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.lifecycle.clone(),
        ))?;
        store.clear_journal()?;
        Ok(RollbackHealthOutcome::Descend)
    } else {
        // Persist the incremented count (phase unchanged) so the next boot resumes the tally.
        persist_transaction(store, tx)?;
        Ok(RollbackHealthOutcome::Retry(tx.rollback_health_failures))
    }
}

fn recovery_transaction(situation: &Situation) -> Option<Transaction> {
    if let Some(tx) = &situation.journal {
        let committed = match &situation.installed {
            Installed::Present(state) => Some(&state.release),
            Installed::Missing | Installed::Invalid => None,
        };
        // A journal is authoritative and decides recovery on its own — it must NEVER fall through
        // to the `Pending` branch below. Drive the rollback hook replay only when the predecessor
        // must actually be restored (`RestorePredecessor`). `Committed` (nothing to undo) and
        // `NeverSwapped` (a pre-activation crash that never displaced the predecessor, or an
        // already-finished rollback/abort) are fully handled by the boot plan alone —
        // `reconcile_transaction` clears the journal and, for a finished rollback, commits the
        // predecessor via its `is_rollback` branch with zero lifecycle calls. Falling through here
        // would let the confirm-window `Pending` branch synthesize a *fresh* `RollbackStarted` and
        // re-run the entire (already-completed) rollback machine — a non-minimal double-invoke of
        // every lifecycle hook.
        return (updated::transaction::classify_recovery(tx, situation.active.as_ref(), committed)
            == updated::transaction::Recovery::RestorePredecessor)
            .then(|| tx.clone());
    }
    if let Installed::Present(installed) = &situation.installed {
        if let Some(pending) = &installed.pending {
            let rollback_started = situation.active.as_ref() == Some(&pending.previous_release);
            if situation.service_exited || rollback_started {
                return Some(Transaction {
                    id: pending.lifecycle_attempt_id.clone(),
                    previous_release: pending.previous_release.clone(),
                    previous_archive_sha256: pending.previous_archive_sha256.clone(),
                    previous_repository_lineage: pending.previous_repository_lineage.clone(),
                    candidate_release: installed.release.clone(),
                    candidate_archive_sha256: installed.archive_sha256.clone(),
                    candidate_repository_lineage: installed.repository_lineage.clone(),
                    candidate_rejection_required: situation.service_exited,
                    lifecycle: pending.lifecycle.clone(),
                    rollback_health_failures: 0,
                    phase: TransactionPhase::RollbackStarted,
                });
            }
        }
    }
    None
}

fn complete_recovery_activation(
    opts: &Options,
    store: &mut dyn Store,
    recovery: Option<&mut Transaction>,
) -> io::Result<()> {
    let Some(tx) = recovery else {
        return Ok(());
    };
    if tx.rollback_rank().is_none_or(|rank| rank >= 4) {
        return Ok(());
    }
    // Restore the predecessor's machine state through the same reconciler operation used for the
    // candidate. Managed mode has already stopped the candidate; provider-managed mode never
    // exposes or manipulates an application PID.
    invoke_deployment_provider(
        tx.lifecycle.as_ref(),
        opts,
        LifecycleInvocation {
            phase: LifecyclePhase::Activate,
            reason: LifecycleReason::Update,
            id: &tx.id,
            pid: None,
            candidate: &tx.previous_release,
            predecessor: &tx.candidate_release,
        },
    )?;
    Chaos::from_env().crossing(update::boundary::PREDECESSOR_LIFECYCLE_APPLIED);
    advance_transaction(store, tx, TransactionPhase::PredecessorActivated)
}

// ============================== boot: gather + execute ==============================

/// Read the whole world the boot planner needs — durable state via the [`Store`] and the
/// guardian's recovery markers — into one [`Situation`]. The shell's single point of input
/// gathering; the marker reads also consume the markers.
fn gather_situation(
    opts: &Options,
    store: &dyn Store,
    guardian_state: Option<&Path>,
    first_install: bool,
) -> io::Result<Situation> {
    let active = store.active_release()?;
    let installed = store.installed();
    let journal = store.journal()?;
    Ok(Situation {
        installed,
        active,
        journal,
        service_exited: match guardian_state {
            Some(state) => guardian::take_service_exit_marker(state)?,
            None => false,
        },
        app_running: guardian::adopted_app_pid(),
        first_install,
        bad_supervisor: match guardian_state {
            Some(state) => guardian::take_rejected_supervisor(state)?,
            None => None,
        },
        confirm_window: opts.timeouts.confirmation_window,
        now: now_unix(),
    })
}

/// Perform a boot [`Plan`]'s durable reconciliation and return the still-unconfirmed
/// update (if any) for the loop to watch.
fn execute_boot_plan(
    plan: &Plan,
    opts: &Options,
    store: &mut dyn Store,
    guardian: &mut Guardian,
    self_update: &mut SelfUpdateState,
    defer_commit: bool,
    mut recovery: Option<&mut Transaction>,
) -> io::Result<Option<Pending>> {
    if let Some(tx) = recovery.as_mut() {
        if tx.rollback_rank().is_some_and(|rank| rank < 1) {
            advance_transaction(store, tx, TransactionPhase::RollbackStopStarted)?;
        }
    }
    let needs_quiesce = recovery
        .as_ref()
        .is_none_or(|tx| tx.rollback_rank().is_some_and(|rank| rank < 2));
    if needs_quiesce {
        if let Some(tx) = recovery.as_ref() {
            invoke_deployment_provider(
                tx.lifecycle.as_ref(),
                opts,
                LifecycleInvocation {
                    phase: LifecyclePhase::Stop,
                    reason: LifecycleReason::Update,
                    id: &tx.id,
                    pid: guardian::adopted_app_pid(),
                    candidate: &tx.previous_release,
                    predecessor: &tx.candidate_release,
                },
            )?;
        }
    }
    if plan.quiesce && needs_quiesce {
        warn("stopping the uncommitted candidate before reconciling its release");
        stop(guardian)?;
    }
    if needs_quiesce && recovery.is_some() {
        Chaos::from_env().crossing(update::boundary::ROLLBACK_STOP_APPLIED);
    }
    if let Some(tx) = recovery.as_mut() {
        if tx.rollback_rank().is_some_and(|rank| rank < 2) {
            advance_transaction(store, tx, TransactionPhase::RollbackStopped)?;
        }
        if tx.rollback_rank().is_some_and(|rank| rank < 3) {
            advance_transaction(store, tx, TransactionPhase::RollbackActivateStarted)?;
        }
    }
    let activate_release = recovery
        .as_ref()
        .is_none_or(|tx| tx.rollback_rank().is_some_and(|rank| rank < 4));
    apply_store_plan(plan, store, defer_commit, activate_release)?;
    if activate_release && !matches!(plan.release, ReleaseFix::None) {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_POINTER_APPLIED);
    }
    if let Some(path) = &plan.reject_supervisor {
        self_update.reject_candidate(path);
    }
    Ok(installed_pending(store))
}

/// Apply the durable half of a boot [`Plan`] to the [`Store`].
fn apply_store_plan(
    plan: &Plan,
    store: &mut dyn Store,
    defer_commit: bool,
    activate_release: bool,
) -> io::Result<()> {
    // Commit the intended state before activation; immutable predecessor releases remain
    // available if a crash interrupts pointer reconciliation.
    if !defer_commit {
        if let Some(state) = &plan.commit {
            store.commit_installed(state)?;
        }
    }
    if activate_release {
        match &plan.release {
            ReleaseFix::None => {}
            ReleaseFix::Activate(release) => store.activate(release)?,
        }
    }
    for (lineage, hash) in &plan.reject_app {
        store.reject(lineage, hash)?;
    }
    Ok(())
}

/// The unconfirmed update recorded in the installed state, if any.
fn installed_pending(store: &dyn Store) -> Option<Pending> {
    match store.installed() {
        Installed::Present(s) => s.pending,
        _ => None,
    }
}

/// The committed release's lifecycle provider.
fn installed_lifecycle_provider(
    store: &dyn Store,
) -> io::Result<Box<updated::state::ProviderRelease>> {
    match store.installed() {
        Installed::Present(state) => Ok(state.lifecycle),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a verified installed release is required",
        )),
    }
}

/// Confirm the current update by clearing its pending record.
/// Returns `true` only once the confirmation is durable, so callers must keep their
/// in-memory pending intent (and continue suppressing updates) after a write failure.
fn confirm_update(store: &mut dyn Store) -> bool {
    if let Installed::Present(mut st) = store.installed() {
        st.pending = None;
        if let Err(e) = store.commit_installed(&st) {
            // Could not durably clear the pending intent; retry on the next tick or boot.
            warn(&format!(
                "could not durably confirm the update ({e}); will retry"
            ));
            return false;
        }
    }
    true
}

// ============================ application updates ============================

fn application_check_due(
    updates_enabled: bool,
    pending: bool,
    now: Instant,
    next_check: Instant,
) -> bool {
    updates_enabled && !pending && now >= next_check
}

fn log(msg: &str) {
    foundation::log::info("supervisor", msg);
}
fn warn(msg: &str) {
    foundation::log::warn("supervisor", msg);
}
fn error(msg: &str) {
    foundation::log::error("supervisor", msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use updated::bundle::ReleaseId;
    use updated::install::InstallTransaction;
    use updated::state::{Installed, InstalledState, RepositoryLineage};
    use updated::transaction::{Phase, Transaction};

    /// A durable-store double that keeps everything in memory, so the counter-persistence loop can
    /// be driven across simulated boots without touching the filesystem.
    #[derive(Default)]
    struct MemStore {
        installed: Option<InstalledState>,
        journal: Option<Transaction>,
        install_journal: Option<InstallTransaction>,
        active: Option<ReleaseId>,
        rejected: HashSet<String>,
    }

    impl Store for MemStore {
        fn installed(&self) -> Installed {
            match &self.installed {
                Some(state) => Installed::Present(Box::new(state.clone())),
                None => Installed::Missing,
            }
        }
        fn journal(&self) -> io::Result<Option<Transaction>> {
            Ok(self.journal.clone())
        }
        fn install_journal(&self) -> io::Result<Option<InstallTransaction>> {
            Ok(self.install_journal.clone())
        }
        fn active_release(&self) -> io::Result<Option<ReleaseId>> {
            Ok(self.active.clone())
        }
        fn is_rejected(&self, lineage: &RepositoryLineage, digest: &str) -> bool {
            self.rejected.contains(&lineage.rejection_key(digest))
        }
        fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
            self.installed = Some(state.clone());
            Ok(())
        }
        fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
            self.journal = Some(tx.clone());
            Ok(())
        }
        fn clear_journal(&mut self) -> io::Result<()> {
            self.journal = None;
            Ok(())
        }
        fn write_install_journal(&mut self, tx: &InstallTransaction) -> io::Result<()> {
            self.install_journal = Some(tx.clone());
            Ok(())
        }
        fn clear_install_journal(&mut self) -> io::Result<()> {
            self.install_journal = None;
            Ok(())
        }
        fn reject(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
            self.rejected.insert(lineage.rejection_key(digest));
            Ok(())
        }
        fn clear_rejection(&mut self, lineage: &RepositoryLineage, digest: &str) -> io::Result<()> {
            self.rejected.remove(&lineage.rejection_key(digest));
            Ok(())
        }
        fn verify_release(&self, _: &ReleaseId) -> io::Result<()> {
            Ok(())
        }
        fn point_active(&mut self, release: &ReleaseId) -> io::Result<()> {
            self.active = Some(release.clone());
            Ok(())
        }
    }

    fn release(version: &str, digest: &str) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    fn provider() -> Box<updated::state::ProviderRelease> {
        Box::new(updated::state::ProviderRelease {
            product: "reconciler".into(),
            release: release("1.0.0", "reconciler-manifest"),
            archive_sha256: "reconciler-archive".into(),
            args: Vec::new(),
            timeout_millis: 1_000,
        })
    }

    #[test]
    fn a_persistently_unhealthy_rollback_target_descends_instead_of_looping() {
        let lineage = RepositoryLineage::from_metadata_url("https://repo/metadata/");
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let tx = Transaction {
            id: "attempt".into(),
            previous_release: predecessor.clone(),
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage.clone(),
            candidate_release: candidate.clone(),
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage.clone(),
            candidate_rejection_required: true,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: Phase::RollbackHealthStarted,
        };
        let mut store = MemStore {
            installed: Some(InstalledState::confirmed(
                lineage.clone(),
                candidate.clone(),
                "archive-two".into(),
                provider(),
            )),
            journal: Some(tx),
            ..MemStore::default()
        };

        // Each iteration models one boot that re-derives the rollback from the durable journal and
        // fails the predecessor's health gate. The loop must terminate (descend), never spin.
        let mut outcomes = Vec::new();
        for _ in 0..MAX_ROLLBACK_HEALTH_ATTEMPTS + 5 {
            let Some(mut derived) = store.journal().unwrap() else {
                break; // journal cleared: we descended, so the next boot no longer rolls back.
            };
            assert!(derived.is_rollback());
            let outcome = bound_unhealthy_rollback(&mut store, &mut derived).unwrap();
            let done = outcome == RollbackHealthOutcome::Descend;
            outcomes.push(outcome);
            if done {
                break;
            }
        }

        assert_eq!(
            outcomes,
            vec![
                RollbackHealthOutcome::Retry(1),
                RollbackHealthOutcome::Retry(2),
                RollbackHealthOutcome::Descend,
            ],
            "the rollback must be bounded at {MAX_ROLLBACK_HEALTH_ATTEMPTS} attempts, then descend"
        );
        // On descent the predecessor's bytes are rejected and it is recorded provisional with the
        // journal cleared — exactly the state `ensure_installed` treats as "descend via ordered
        // fallback past this head" on the next boot.
        assert!(store.is_rejected(&lineage, "archive-one"));
        assert!(store.journal().unwrap().is_none());
        match store.installed() {
            Installed::Present(state) => {
                assert_eq!(state.release, predecessor);
                assert!(
                    !state.confirmed,
                    "the descended-from predecessor is recorded provisional so cold install re-descends"
                );
            }
            _ => panic!("expected a provisional predecessor record"),
        }
    }
}
