//! The node agent: a package runner. It pulls signed TUF bundles, activates them through a
//! durable transaction, and invokes the release's own reconciler hooks — `apply`, `healthcheck`,
//! `rollback`, `inspect`. It never launches, signals, or holds a PID of any workload. The agent
//! is itself replaceable, by pointer flip through the launcher.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use updated::config::{with_suffix, Application, Paths, Routing, Storage, Timeouts};
/// The reconciler protocol vocabulary is defined once, in the contracts crate, and shared with
/// every reconciler implementation in this workspace.
use updated_contracts::reconciler::{attempt, Operation};
use updated_contracts::telemetry::REPORT_CADENCE_JITTER_PERCENT;
mod acquire;
mod boot;
mod domain;
mod fingerprint;
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

use boot::{plan_boot, GateFailure};
use domain::*;
use guardian::Guardian;
use install::ensure_installed;
use options::*;
use schedule::*;
use selection::*;
use self_update::*;
use store::*;
use update::*;

use updated::hash::sha256_file;
use updated_tuf::select::{target_sha, SelectedRelease};
use updated_tuf::{DefaultPolicy, TrustedRepository};

/// This agent build's version, baked in (see `build.rs`). Self-update selection is
/// by content hash, not this — it is for logs and for distinguishing builds.
const SELF_VERSION: &str = env!("SUPERVISOR_VERSION");

struct Options {
    deployment: String,
    routing: Routing,
    application: Application,
    timeouts: BoundedTimeouts,
    storage: Storage,
    /// Canonical bundle installation layout.
    paths: Paths,
    supervisor_update: SupervisorUpdate,
    secrets: secrets::SecretManager,
    identity_renewal: IdentityRenewal,
}

struct IdentityRenewal {
    bootstrap: PathBuf,
    state_dir: PathBuf,
}

impl Options {
    /// Reconcile the managed runtime against the live assignment resolved this cycle. The
    /// runtime (health checks, cadence, retention, secrets, inputs) is signed into the SAME
    /// assignment that carries the version and provider set, so a control-plane reassignment
    /// can change it with no version bump. The version/provider are reconciled by
    /// `check_application`; this reconciles everything else onto the one live source.
    ///
    /// Returns whether the machine is stale on the new runtime — changed secrets or resolved
    /// `inputs` reach the release only through a reconciler invocation (its environment and its
    /// `--input-file`), so the caller answers this by running the environment converge
    /// (`converge_environment`), which is the one thing that can act on them.
    fn apply_runtime(&mut self, runtime: &updated_contracts::assignment::ManagedRuntime) -> bool {
        let converge = self.application.secrets != runtime.secrets
            || self.application.inputs != runtime.inputs;
        // `install_root` needs no reconciliation: `TrustedRepository::assigned` fails closed on
        // any assignment whose root is not exactly the one this process resolved its paths from
        // (`usable_as_boot_config`), so an assignment that reaches here can only carry the boot
        // root. Moving a node's install root is a migration, done by restarting on a new config.
        self.application = Application::from_runtime(runtime);
        self.timeouts = BoundedTimeouts::new(Timeouts::from_runtime(runtime));
        self.storage = Storage::from_runtime(runtime);
        // The agent's OWN update rides the same assignment: its channel and cadence are the
        // application's, seeded once at `parse_args` from the boot-time config. Reconcile them here
        // too, or a node the control plane moves from `stable` to `canary` keeps selecting the
        // `supervisor` product from `stable` — and keeps checking on the old cadence — for as long
        // as the process lives, since nothing else ever rewrites these two fields.
        self.supervisor_update.channel = self.application.channel.clone();
        self.supervisor_update.check_interval = self.timeouts.supervisor_check_interval;
        converge
    }
}

/// The agent stages a verified release from the reserved `supervisor` product
/// into the launcher's content-addressed state directory and hands it off for a
/// readiness-gated replacement.
struct SupervisorUpdate {
    channel: String,
    /// The launcher's state directory, holding `supervisors/<id>/` staging dirs.
    state_dir: PathBuf,
    check_interval: Duration,
}

/// Mutable bookkeeping for the update-check loop: the metadata-refresh backoff and the next
/// application-update and identity deadlines.
struct LoopState {
    refresh_failures: u32,
    next_app_check: Instant,
    next_identity_check: Instant,
}

impl LoopState {
    fn new(check_interval: Duration) -> Self {
        Self {
            refresh_failures: 0,
            next_app_check: Instant::now() + jitter(check_interval, REPORT_CADENCE_JITTER_PERCENT),
            next_identity_check: Instant::now(),
        }
    }
}

/// Steady-state health tracking for the deployed release: when the next `healthcheck` invocation
/// is due, and the last observation (what the node's report carries as `settled`).
///
/// Health is the reconciler's answer and nothing else — the agent owns no workload process to
/// observe — so a probe is an observation, never a verdict that ends this process. Only the boot
/// gate, inside a confirmation window, turns unhealth into action.
///
/// Every converge outside the loop proves the release healthy before returning: boot and the
/// update transaction both gate on [`update::became_healthy`], which polls for the configured
/// `health_grace`. A converge the loop performs itself has no such gate, so this type is where that
/// grace is applied instead: [`HealthWatch::reconverged`] is the single way the loop restarts the
/// tracking, and it is what keeps a freshly re-applied release from being reported unready while
/// the reconciler is still bringing it up.
struct HealthWatch {
    next_probe: Instant,
    /// Latest readiness observation, so a report reflects whether the deployed release is
    /// actually serving. `None` until first sampled, or until a converge discards it.
    last_ready: Option<bool>,
}

/// Everything the 12-hourly identity tick may spend on the control loop, end to end.
///
/// Sized by the health path, not by the work. The tick runs inline on the single loop that also
/// emits the rollout heartbeat, and the healthproxy drains a node whose report is older than
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`], so the whole tick has to stay well inside
/// that window or the renewal walk causes the drain it is meant to protect. Its own network legs
/// are bounded independently and generously (a 60s control-plane deadline twice, plus a 30s root
/// catch-up walk), which against a gateway that accepts connections and then trickles bytes adds
/// up to more than two missed heartbeats; this is the bound that makes that impossible. Timing out
/// is cheap — the whole check is simply retried on the next 12h tick.
const IDENTITY_TICK_DEADLINE: Duration = Duration::from_secs(20);

impl HealthWatch {
    /// Start watching a release the boot gate has just observed, so the first steady-state probe
    /// is one ordinary interval away and the report already carries what that gate saw.
    fn after_boot_gate(timeouts: &Timeouts, ready: bool) -> Self {
        HealthWatch {
            next_probe: Instant::now() + timeouts.health_interval,
            last_ready: Some(ready),
        }
    }

    /// Re-arm after the loop ran a converge of its own (a runtime reassignment, a secret rotation,
    /// repaired bytes). Nothing has proven the re-applied release healthy, so give the reconciler
    /// the same configured `health_grace` every gated converge gets through `became_healthy`
    /// before a probe is recorded against it.
    ///
    /// Without the grace, a release that is merely still starting is reported unready — fleet-wide
    /// and simultaneously, on a benign reassignment — and the healthproxy drains every node that
    /// obeyed the assignment.
    fn reconverged(&mut self, timeouts: &Timeouts) {
        self.next_probe = Instant::now() + timeouts.health_grace;
        self.last_ready = None;
    }

    /// Record one periodic observation and schedule the next probe.
    fn observed(&mut self, now: Instant, healthy: bool, timeouts: &Timeouts) {
        self.next_probe = now + timeouts.health_interval;
        self.last_ready = Some(healthy);
    }
}

fn main() {
    // The chaos-feature build can enumerate its own transaction boundaries, so the e2e
    // drives exactly the crossings the agent defines instead of a hand-copied list.
    #[cfg(feature = "chaos")]
    if let Some(kind) = std::env::args().find(|a| {
        a == "--list-chaos-boundaries"
            || a == "--list-rollback-chaos-boundaries"
            || a == "--list-install-chaos-boundaries"
    }) {
        let boundaries = match kind.as_str() {
            "--list-rollback-chaos-boundaries" => update::ROLLBACK_BOUNDARIES,
            "--list-install-chaos-boundaries" => install::INSTALL_BOUNDARIES,
            _ => update::BOUNDARIES,
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
    let _lock = updated::lock::InstanceLock::acquire(&with_suffix(&opts.paths.installed, ".lock"))
        .map_err(|e| format!("another supervisor already owns this install: {e}"))?;

    // Watch for a stop/restart signal; when it fires the agent exits. It touches no workload:
    // whatever the release's reconciler started keeps running, under whatever owns it.
    let shutdown = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_shutdown_signal().await;
            shutdown.store(true, Ordering::SeqCst);
        }
    });

    let mut guardian =
        Guardian::connect().map_err(|e| format!("connecting to the launcher: {e}"))?;

    let mut store = FileStore::open(opts.paths.clone())?;

    // Reconcile any in-flight install journal and cold-install a fresh node, returning whether
    // this boot performed the install. That selects the boot converge's reason (install vs.
    // restart) so an operator script can seed on first boot and merely clean up on later
    // restarts. All first-install placement happens inside this durable, crash-recoverable
    // install; there is no first-install branch after it.
    let first_install = ensure_installed(&opts, &mut store).await?;

    // Claim the launcher's marker once, up front.
    let mut evidence = guardian::Evidence::read(guardian::state_dir().as_deref())?;

    // Whether this boot repaired a damaged committed tree. A permanent, hash-keyed rejection may
    // never be charged to bytes this boot re-downloaded and re-verified, so it is the one input
    // the boot gate's rejection decision needs that no durable record holds.
    let mut bytes_repaired = false;

    // The disk is not trusted merely because it was verified during installation. This
    // check is local and deliberately precedes every repository access. A modified
    // committed bundle is never converged onto, even when the network is unavailable.
    if let updated::state::Installed::Present(installed) = store.installed() {
        if let Err(error) =
            updated::bundle::verify_release(&opts.paths.versions, &installed.release)
        {
            // The repaired-from repository is of no use on the boot path — there is no loop tick to
            // report for yet, and the ordinary heartbeat starts one refresh later.
            let _repo = repair_committed_bundle(&opts, &mut store)
                .await
                .map_err(|repair| {
                    format!(
                        "committed application bundle failed local verification ({error}); no signed repair was applicable: {repair}"
                    )
                })?;
            // The boot gate below may fail on a release whose tree this boot just repaired. That
            // failure is evidence about this disk, not about the release — the same reasoning that
            // forbids `repair_committed_bundle` from rejecting the corrupt archive — so it still
            // drives the revert (reversible) but never the permanent, hash-keyed rejection. One
            // boot deep: the next boot finds an intact tree, and a release that fails its gate
            // again is charged for it, so the descent still terminates.
            bytes_repaired = true;
        }
    }

    // Gather the whole world into a Situation and let the pure boot planner decide everything:
    // recovery, drift enforcement, journaled rejections, and pending confirmation. The
    // rejected-agent claim is surrendered — and only then is its file erased — at the point the
    // durable consequence it implies has landed.
    let situation = gather_situation(&opts, &store, &evidence)?;
    let mut recovery_transaction = recovery_transaction(&situation);
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
    let mut current = plan.current.clone();

    let mut self_update = SelfUpdateState::load(&opts)?;

    // A confirmation-window revert starts rollback by materializing the same phase journal
    // used by ordinary activation failures. From this write onward there is exactly one
    // recovery path, including if this agent dies before touching the pointer.
    //
    // The guard is "the journal on disk is not already this transaction", not "there is no
    // journal": a SPENT journal (the update's commit landed, but its terminal write or its
    // clearing did not) leaves a file on disk while the rollback being driven is synthesized from
    // `pending`, and that synthesized intent has to become durable too — otherwise a crash mid-
    // recovery re-reads the spent journal and derives the rollback from scratch.
    if defer_recovery_commit && situation.journal.as_ref() != recovery_transaction.as_ref() {
        persist_transaction(
            &mut store,
            recovery_transaction
                .as_ref()
                .expect("pending lifecycle recovery has a transaction"),
        )?;
    }
    if let Some(tx) = recovery_transaction.as_mut() {
        // Move a forward transaction onto the rollback path so its resume gates open. Every
        // recovery that reaches here can make this transition: `boot::journal_recovery` refuses to
        // hand back a journal whose phase cannot drive a rollback (a terminal `Committed` or
        // `RolledBack` file left behind by a tolerated `clear_journal` failure), and the
        // `pending`-derived rollbacks are synthesized already on the path.
        if !tx.is_rollback() {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackStarted)?;
        }
    }

    // Perform the plan's durable reconciliation (binary, rejections, commit), yielding the
    // still-unconfirmed update (if any) for the loop to confirm once its window passes.
    // A failure here leaves the journal and the unspent marker claim intact and EXITS (see
    // `exit_for_relaunch`), so the launcher relaunches this agent and boot recovery re-derives
    // the identical, idempotent reconciliation from that durable evidence — unless the cause is a
    // node-local transient, which `recover_through_transients` waits out instead (see there).
    let mut pending = recover_through_transients(
        "boot/update recovery",
        &TransientRetry::BOOT,
        &mut guardian,
        &shutdown,
        || {
            execute_boot_plan(
                &plan,
                &mut store,
                &mut self_update,
                defer_recovery_commit,
                recovery_transaction.as_mut(),
                &mut evidence,
            )
        },
    )
    .await?;
    // Restore the predecessor's machine state (rollback recovery): the predecessor's own `apply`,
    // replayed under the transaction's identity — `complete_recovery_activation` resolves whether
    // this boot still owes it.
    recover_through_transients(
        "predecessor activation recovery",
        &TransientRetry::BOOT,
        &mut guardian,
        &shutdown,
        || complete_recovery_activation(&opts, &mut store, recovery_transaction.as_mut()),
    )
    .await?;
    if pending.is_some() {
        if let Some(v) = current.as_deref() {
            log(&format!(
                "update {v} is unconfirmed; a failed health gate within its window reverts it"
            ));
        }
    }

    log(&format!(
        "agent {SELF_VERSION} running packages in {:?} (product {} channel {}, installed {}, check every {}s)",
        opts.paths.install_root,
        opts.application.product,
        opts.application.channel,
        current.as_deref().unwrap_or("none"),
        opts.timeouts.check_interval.as_secs()
    ));

    // Signal *agent* readiness to the launcher now that this boot has reconciled its durable
    // state — BEFORE fetching secrets or gating the release's health. For a committed agent this is
    // a no-op; for a candidate it begins the launcher's confirmation window. Signalling here
    // decouples "the agent process started successfully" from everything downstream that depends on
    // the control plane or on the release: neither a slow reconciler nor an unreachable secrets
    // endpoint can blow the launcher's ready_timeout and get a perfectly good agent rejected — and
    // that rejection is by content hash and never expires.
    //
    // The price is real and deliberate: from here the confirmation window runs on its own clock, so
    // a candidate that spends it waiting for secrets is committed WITHOUT having converged the
    // release, and the boot converge and health gate below both run inside the window rather than
    // in front of it. That is the trade this ordering buys — commitment attests these agent bytes
    // started and stayed up, not that the control plane was reachable or that the release is
    // healthy.
    let ready = guardian.signal_ready();
    #[cfg(all(feature = "chaos", supervisor_chaos_exit_after_ready))]
    {
        eprintln!("supervisor: CHAOS: exiting after readiness, before guardian confirmation");
        std::process::exit(137);
    }

    // Acquire the assigned secrets, waiting out a control-plane outage: every reconciler
    // invocation carries them in its environment, so no hook may run without them. `ready` is the
    // proof that this wait sits behind the readiness signal — in front of it, an unreachable
    // secrets endpoint is indistinguishable from an agent binary that cannot start, and gets the
    // candidate's bytes rejected for good.
    if !opts
        .secrets
        .acquire(
            &opts.deployment,
            &opts.application.secrets,
            &shutdown,
            ready,
        )
        .await
    {
        log("shutdown requested while waiting for the assigned secrets; exiting");
        return Ok(());
    }

    // The boot converge: the committed release's own `apply`, so the reconciler brings the machine
    // onto what this boot just reconciled. A boot that is resuming an interrupted update or
    // rollback (recovery_transaction is Some) must replay only that transaction's minimal,
    // idempotent steps — injecting a fresh per-boot `apply` there would run the reconciler outside
    // the transaction — so it fires only on an ordinary boot.
    if recovery_transaction.is_none() {
        converge_environment(
            &opts,
            &store,
            if first_install {
                LifecycleReason::Install
            } else {
                LifecycleReason::Restart
            },
        )?;
    }
    if let Some(tx) = recovery_transaction.as_mut() {
        if tx.recovery_pending(TransactionPhase::RollbackHealthStarted) {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackHealthStarted)?;
        }
    }
    // Gate readiness: the release's own `healthcheck` must pass before this boot is trusted. It is
    // the only health source — the agent owns no workload process to observe — and readiness was
    // signalled long before it, so for a candidate agent a failure here is an exit *inside* the
    // launcher's confirmation window.
    //
    // During a crash-recovered rollback the predecessor commit is deferred until *after* this gate,
    // so `store.installed()` still holds the CANDIDATE record. Gate the restored predecessor with
    // ITS OWN lifecycle provider — carried in the recovery transaction from `pending` (the operator
    // set staged for exactly this rollback) — not the candidate's. Otherwise an update that revised
    // the lifecycle provider, then failed, would gate the healthy predecessor with the candidate's
    // hooks, reject it, and crash-loop a good release.
    let installed_state = match store.installed() {
        Installed::Present(installed) => installed,
        _ => return Err("cannot verify a boot without an installed release".into()),
    };
    // Identity and providers are resolved together, from one source, so the gate can never observe
    // one release with another's hooks.
    let (installed, installed_lifecycle) =
        boot_gate_target(recovery_transaction.as_ref(), &installed_state);
    let mut reconciler = ReleaseReconciler::new(&opts, installed_lifecycle.as_ref());
    let gate = update::became_healthy(&mut reconciler, attempt::BOOT, &installed, &installed).await;
    if let update::Health::Inconclusive(cause) = &gate {
        // No verdict about these bytes: the probes stopped reaching the node reconciler (a corrupt
        // or pruned provider tree, ENOSPC/EACCES/EIO preparing the invocation), so this says more
        // about the disk than about the release. Note it — and then fall through to the SAME
        // bounded failure path an unhealthy gate takes: these faults are deterministic (a provider
        // tree that will not resolve resolves no better on the next boot), so treating them as
        // "try again later" would relaunch into the identical failure forever.
        warn(&format!(
            "the boot readiness gate could not reach the node reconciler ({cause}); treating it as \
             a failed gate so the bounded recovery below still terminates"
        ));
    }
    let gate_passed = matches!(gate, update::Health::Ready);
    if !gate_passed {
        // A crash-recovered rollback whose restored predecessor cannot pass the gate is the
        // dangerous case: the still-deferred `store.installed()` holds the CONFIRMED candidate, not
        // the predecessor, so without a bound the launcher relaunches, the journal re-derives the
        // identical rollback, and it runs forever with nothing converged. Bound it: count failures
        // durably in the journal (which is what survives the relaunch) and, once the limit is hit,
        // reject the predecessor's bytes and descend via the same ordered-fallback path a cold
        // install uses.
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
            return Err("the rollback target failed its health gate".into());
        }
        // Otherwise the answer is the committed record's alone: revert inside a confirmation
        // window, reject a never-proven provisional head, or merely report. See
        // [`boot::plan_gate_failure`].
        match store.installed() {
            Installed::Present(state) => match boot::plan_gate_failure(&state) {
                GateFailure::Revert => {
                    if let Err(error) = revert_unconfirmed_head(&mut store, &state, bytes_repaired)
                    {
                        return Err(exit_for_relaunch("recording the revert", &error));
                    }
                    return Err(
                        "the unconfirmed release failed its boot health gate; reverting on the \
                         next boot"
                            .into(),
                    );
                }
                GateFailure::RejectProvisional => {
                    if let Err(error) = reject_provisional_head(&mut store, &state) {
                        return Err(exit_for_relaunch(
                            "rejecting the failed provisional head",
                            &error,
                        ));
                    }
                    return Err("the provisional head failed its boot health gate".into());
                }
                // A confirmed release that is unhealthy is REPORTED, never reverted locally: the
                // reconciler owns the workload and may converge it later, and there is no
                // predecessor image left to revert to. Exiting instead would hand the node to the
                // init system's restart loop with nothing to fix on the next boot.
                GateFailure::Report => warn(&format!(
                    "the committed release {} is unhealthy; reporting it and continuing to \
                     reconcile",
                    state.release.version
                )),
            },
            _ => return Err("cannot verify a boot without an installed release".into()),
        }
    }
    // The head has now proven healthy this boot: confirm it so a later transient unhealth of this
    // (proven) head is reported and reconciled, not rejected as a broken head.
    if gate_passed {
        if let updated::state::Installed::Present(mut state) = store.installed() {
            if state.confirm() {
                if let Err(error) = store.commit_installed(&state) {
                    warn(&format!("confirming the proven head failed: {error}"));
                }
            }
        }
    }
    if recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.recovery_pending(TransactionPhase::PredecessorHealthy))
    {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_HEALTH_APPLIED);
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::PredecessorHealthy)?;
    }

    // A crash may have interrupted the rollback between its journal barriers. Once the
    // predecessor is healthy again, replay the idempotent `rollback` operation with the same
    // transaction identity before declaring this boot recovered.
    let rollback_incomplete = recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.recovery_pending(TransactionPhase::RolledBack));
    if rollback_incomplete {
        if let Some(tx) = recovery_transaction.as_mut() {
            if tx.recovery_pending(TransactionPhase::RollbackFinalizeStarted) {
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
                    phase: Operation::Rollback,
                    reason: LifecycleReason::Update,
                    id: &tx.id,
                    candidate: &tx.previous_release,
                    predecessor: &tx.candidate_release,
                },
            ) {
                return Err(exit_for_relaunch("rollback recovery hook", &error));
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
    // have succeeded. If this agent dies, the next boot sees the same evidence and repeats the
    // idempotent recovery instead of declaring success.
    if plan.clear_journal || defer_recovery_commit {
        store.clear_journal()?;
    }
    garbage_collect(&opts, &store);

    let mut loop_state = LoopState::new(opts.timeouts.check_interval);
    // The boot gate is this boot's first observation, whichever way it went: steady-state probing
    // starts one interval from here, and the node's first report carries what the gate saw rather
    // than claiming nothing is known. Pool membership follows from that report — the healthproxy is
    // the only path into rotation, and this agent never touches it directly.
    let mut health = HealthWatch::after_boot_gate(&opts.timeouts, gate_passed);
    // Rollout telemetry: this node's identity and a client for best-effort reports. Both
    // are inert unless the current assignment carries a report URL; a node without a
    // derivable identity or a failing client simply never reports and updates as usual.
    //
    // The report endpoint is the fleet gateway, which admits only fleet-CA client certs — the
    // same mTLS the node already uses to fetch its repository — so the telemetry client presents
    // the node's identity. If that identity can't build (an offline/non-mTLS deployment with no
    // CA on disk), fall back to a plain client: telemetry is best-effort, and a plain-HTTP report
    // target is served as usual.
    let heartbeat = Heartbeat {
        client: opts
            .routing
            .mtls
            .reqwest_client()
            .unwrap_or_else(|_| reqwest::Client::new()),
        node: telemetry::node_identity(&opts.routing),
        // The node signs each report with the SAME per-node key that certifies its mTLS leaf, so
        // the control plane verifies authenticity end-to-end (not just on the write hop). Loaded
        // once as PKCS#8 DER; absent only for a mis-provisioned node, whose unsigned reports then
        // fail closed at the throttle (treated as not-yet-settled) rather than being trusted.
        signing_key: std::fs::read_to_string(&opts.routing.mtls.client_key)
            .ok()
            .and_then(|pem| updated::csr::key_pem_to_pkcs8_der(&pem).ok()),
    };
    let mut fingerprints = fingerprint::Tracker::new(Instant::now());
    // The last repository this node resolved. Kept across cycles so the heartbeat has something to
    // report off even on a cycle that could not reach the control plane: the report endpoint and
    // the metadata endpoint fail independently, and a node that cannot refresh is exactly the node
    // whose silence would be misread as death.
    let mut last_repo: Option<TrustedRepository> = None;
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
        // The cycle clock always bounds the wait — it is the node's report cadence, and a sleep
        // longer than it is a report older than it. The confirmation window only ever shortens it,
        // so the confirm above happens the moment the window ends even when the cycle is longer.
        let mut app_wait = loop_state.next_app_check.saturating_duration_since(now);
        if let Some(p) = pending.as_ref() {
            if !confirm_failed {
                // When the confirm has already failed the window remaining is zero, and letting it
                // set the wait would drop it to its 100ms floor: a confirm that cannot be persisted
                // (a full or read-only state dir) would re-attempt — and re-warn — ten times a
                // second for as long as the fault lasts. The cycle cadence alone then paces it.
                app_wait = app_wait.min(window_remaining(
                    p,
                    opts.timeouts.confirmation_window,
                    now_unix(),
                ));
            }
        }
        let mut wait = app_wait.min(self_update.due_in(now));
        wait = wait.min(health.next_probe.saturating_duration_since(now));
        wait = wait.min(
            loop_state
                .next_identity_check
                .saturating_duration_since(now),
        );
        let wait = wait.max(Duration::from_millis(100));

        if sleep_interruptible(wait, &shutdown).await {
            log("shutdown requested; exiting (the guardian stops the application)");
            return Ok(());
        }

        let now = Instant::now();
        if now >= loop_state.next_identity_check {
            const IDENTITY_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
            loop_state.next_identity_check = now + IDENTITY_CHECK_INTERVAL;
            match updated::enrollment::BootstrapConfig::load(&opts.identity_renewal.bootstrap) {
                Ok(bootstrap) => {
                    // The refresh policy reads the repository's published versioned roots to walk a
                    // rotation the node was offline for, so it presents the same steady-state
                    // identity every other metadata fetch does.
                    let renewal = match bootstrap
                        .enrollment
                        .steady_identity(&opts.identity_renewal.state_dir)
                    {
                        Ok(mtls) => {
                            // ONE deadline over the whole tick, not per network leg. The tick runs
                            // inline on this loop — the same loop that emits the heartbeat below —
                            // and the healthproxy drains a node whose report is older than
                            // REPORT_FRESHNESS (60s). Its three exchanges are each bounded
                            // independently (60s + 30s + 60s), which sums to two and a half missed
                            // heartbeats against a gateway that accepts connections and then
                            // trickles: the walk would cause exactly the drain its own deadline
                            // was sized to prevent. Timing out costs nothing — the whole check is
                            // retried in 12h — so it is bounded well inside that window instead.
                            match tokio::time::timeout(
                                IDENTITY_TICK_DEADLINE,
                                updated::enrollment::renew_node_material_if_due(
                                    &bootstrap,
                                    &opts.identity_renewal.state_dir,
                                    &updated_tuf::EmbeddedChainPolicy::new(mtls),
                                ),
                            )
                            .await
                            {
                                Ok(renewal) => renewal,
                                Err(_) => Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    format!(
                                        "node material renewal exceeded {}s on this control loop",
                                        IDENTITY_TICK_DEADLINE.as_secs()
                                    ),
                                )),
                            }
                        }
                        Err(error) => Err(error),
                    };
                    match renewal {
                        Ok(true) => {
                            log("renewed node certificate; restarting to rebuild authenticated clients");
                            return Ok(());
                        }
                        Ok(false) => {}
                        Err(error) => warn(&format!(
                            "node material renewal check failed; retrying in 12h: {error}"
                        )),
                    }
                }
                Err(error) => warn(&format!(
                    "loading bootstrap for node material renewal failed; retrying in 12h: {error}"
                )),
            }
        }
        if now >= health.next_probe {
            // One periodic `healthcheck` per tick is the node's whole readiness answer, invoked
            // through the provider the committed record names *now* — see `probe_steady_target`,
            // which is why this tick's target exists only inside the call. It is reported, never
            // acted on: past the confirmation window the reconciler owns the workload, and the
            // control plane owns what to do about an unhealthy one.
            let healthy = probe_steady_target(&store, |installed, lifecycle| {
                let healthy = run_lifecycle_command(
                    lifecycle,
                    &opts,
                    LifecycleInvocation {
                        phase: Operation::Healthcheck,
                        reason: LifecycleReason::Restart,
                        id: attempt::PERIODIC,
                        candidate: installed,
                        predecessor: installed,
                    },
                )
                .is_ok();
                if let Some(Err(error)) = fingerprints.poll(
                    now,
                    healthy,
                    heartbeat.node.as_deref().unwrap_or("unidentified-node"),
                    || {
                        prepare_fingerprint_job(
                            lifecycle,
                            &opts,
                            LifecycleInvocation {
                                phase: Operation::Inspect,
                                reason: LifecycleReason::Restart,
                                id: attempt::FINGERPRINT,
                                candidate: installed,
                                predecessor: installed,
                            },
                        )
                    },
                ) {
                    warn(&format!(
                        "node fingerprint observation failed ({error}); omitting it from telemetry"
                    ));
                }
                healthy
            })?;
            health.observed(now, healthy, &opts.timeouts);
        }
        let self_due = self_update.due(now);
        let cycle = cycle_due(pending.is_some(), now, loop_state.next_app_check);
        if !self_due && !cycle.due {
            continue;
        }
        if cycle.due {
            // Advance the cycle clock ONCE, up front. This is the node's report cadence as much as
            // its update cadence, and the early exits below only ever replace this baseline with
            // their own retry.
            loop_state.next_app_check = Instant::now()
                + jitter(opts.timeouts.check_interval, REPORT_CADENCE_JITTER_PERCENT);
        }
        // The cycle's work, as ONE expression. Every early exit inside leaves the block, not the
        // tick, so the heartbeat below is reached however the cycle ends — no `continue` added here
        // later can spend the node's freshness budget in silence.
        let flow: Result<TickFlow, Box<dyn std::error::Error>> = async {
            if let updated::state::Installed::Present(installed) = store.installed() {
                if let Err(error) =
                    updated::bundle::verify_release(&opts.paths.versions, &installed.release)
                {
                    fingerprints.restart_after_deployment(Instant::now());
                    let repaired_from = repair_committed_bundle(&opts, &mut store)
                        .await
                        .map_err(|repair| {
                            format!(
                                "committed application bundle changed on disk ({error}); no signed repair was applicable: {repair}"
                            )
                        })?;
                    current = match store.installed() {
                        updated::state::Installed::Present(state) => Some(state.release.version),
                        _ => None,
                    };
                    // Re-derive the in-memory confirmation intent from the record the repair just
                    // wrote, exactly like every other divergence site. The repair CARRIES an in-flight
                    // update's `pending` forward, so blanking it here would leave a durable `pending`
                    // this process can never confirm (only `confirm_due` -> `confirm_update`, off this
                    // local, clears it) — and the first failed health gate days later would be read
                    // by the boot gate as an unconfirmed release inside its window: a revert to the
                    // predecessor plus a permanent rejection of a release that had long since proven
                    // itself.
                    pending = installed_pending(&store);
                    // The SAME converge the runtime arm below runs, for the same reason: the
                    // reconciler owns every workload process, so `apply` is the only step that puts
                    // the repaired bytes into service. Without it the tampered image would keep
                    // running and the next probe would report it ready. NOT best effort: a converge
                    // that fails would leave the old image serving, so it propagates and this agent
                    // exits, leaving boot recovery to converge the repaired release.
                    converge_environment(&opts, &store, LifecycleReason::Restart).map_err(|error| {
                        format!("converging the environment onto the repaired bundle: {error}")
                    })?;
                    health.reconverged(&opts.timeouts);
                    // Take the repaired bundle through a LATER tick rather than falling through to the
                    // update check on this one: the check is legitimately due against the repaired
                    // release, but reaching it here would drive a whole update transaction over a
                    // release the reconciler has only just been asked to converge onto.
                    //
                    // On the normal cadence, and deferring the self-update check with it, for the same
                    // reason the secrets arm below does: `check` is the only thing that advances the
                    // self-update clock and this early exit skips it, so scheduling the next cycle
                    // immediately would leave `self_due` true forever and collapse `wait` to its 100 ms
                    // floor. Drift that survives a repair (a reconciler `apply` writing into the
                    // content-addressed release directory) would then re-run a full TUF refresh,
                    // re-download and converge ten times a second, forever.
                    let retry = jitter(opts.timeouts.check_interval, REPORT_CADENCE_JITTER_PERCENT);
                    loop_state.next_app_check = Instant::now() + retry;
                    self_update.defer(Instant::now() + retry);
                    // Hand the repository the repair resolved to the heartbeat below. That report is
                    // the node's only word about itself, and this arm is one of the paths that ends a
                    // cycle early — under drift that survives the repair (the arm's own stated case) a
                    // silent cycle would drain the node one `REPORT_FRESHNESS` later for a reason no
                    // reader can see. It reports not-settled, which is simply what `reconverged`
                    // just made true.
                    //
                    // The predecessor fallback resolves no repository — it runs when the control plane
                    // is unreachable — so the heartbeat then reports off the last one this node saw.
                    if let Some(repo) = repaired_from {
                        last_repo = Some(repo);
                    }
                    return Ok(TickFlow::Next);
                }
            }

            // Resolve the agent document afresh, then load its release repository.
            // One verified result serves application and self checks this cycle, and a
            // control-plane reassignment therefore takes effect without process restart.
            let resolved = match TrustedRepository::assigned(&opts.routing, &opts.storage, &opts.paths)
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
                    loop_state.next_app_check =
                        Instant::now() + jitter(retry, REPORT_CADENCE_JITTER_PERCENT);
                    self_update.defer(Instant::now() + retry);
                    return Ok(TickFlow::Next);
                }
            };
            // The one place a resolved repository is remembered, so the heartbeat at the end of the
            // cycle can report off it however this cycle ends.
            last_repo = Some(resolved);
            let repo = last_repo.as_ref().expect("stored on the line above");
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
                        let retry = jitter(opts.timeouts.refresh_retry, REPORT_CADENCE_JITTER_PERCENT);
                        loop_state.next_app_check = Instant::now() + retry;
                        // Defer the self-update check too. It is due right after boot and is only
                        // advanced by `check` below — which this early exit skips — so leaving it alone
                        // collapses `wait` to its 100 ms floor and turns a failing secrets endpoint into
                        // every node in the fleet re-running a TUF refresh and a secrets fetch ten times
                        // a second, against the control plane that is already unwell.
                        self_update.defer(Instant::now() + retry);
                        return Ok(TickFlow::Next);
                    }
                };
                opts.deployment = assignment.deployment.clone();
                if opts.apply_runtime(&assignment.runtime) || secrets_changed {
                    // The runtime changed under the deployed release. Resolved `inputs` reach the
                    // reconciler only as `--input-file`, and rotated secret values only in its
                    // environment, so `apply --reason restart` is the one thing that can act on
                    // either — the agent has no process of its own to reconfigure.
                    log("assignment runtime changed; converging the environment onto it");
                    fingerprints.restart_after_deployment(Instant::now());
                    // The SAME converge the boot path runs, through the same function. Readiness
                    // comes back only through the ordinary observed-healthy path once `reconverged`
                    // re-arms probing, so a converge that fails leaves this node reporting unready.
                    converge_environment(&opts, &store, LifecycleReason::Restart).map_err(|error| {
                        format!("converging the environment onto the new runtime: {error}")
                    })?;
                    // Re-gate readiness from scratch — under the configured start grace, since
                    // nothing has proven the re-applied release yet — and let the next tick drive
                    // the version/provider reconciliation against it.
                    health.reconverged(&opts.timeouts);
                    loop_state.next_app_check = Instant::now();
                    return Ok(TickFlow::Next);
                }
            }

            // Self-update first: on an accepted handoff this process exits.
            if self_due {
                self_update
                    .check(&opts.supervisor_update, repo, &mut guardian)
                    .await;
            }

            if cycle.updates {
                match check_application(&opts, repo, &mut store, || {
                    fingerprints.restart_after_deployment(Instant::now());
                })
                .await
                {
                    AppOutcome::Upgraded { version } => {
                        current = Some(version);
                        // The commit recorded the update as unconfirmed; pick it up so its
                        // window is watched and a crash is caught on the next boot.
                        pending = installed_pending(&store);
                        garbage_collect(&opts, &store);
                        // The transaction converged the machine onto a new release. What this
                        // watch holds — the last observation, the probe deadline set earlier in
                        // this same tick — describes the release it replaced, so re-arm as at
                        // every other converge rather than judging a fresh release on its
                        // predecessor's record.
                        health.reconverged(&opts.timeouts);
                    }
                    AppOutcome::Unchanged => {}
                    AppOutcome::RestartForRecovery => {
                        // A post-activation failure left a durable rollback journal. Terminate this
                        // disposable agent cleanly; the launcher relaunches it and boot recovery
                        // performs the rollback (the single rollback path).
                        log("update failed after activation; restarting so boot recovery rolls back");
                        return Ok(TickFlow::Exit);
                    }
                    AppOutcome::Fatal(message) => {
                        return Err(exit_for_relaunch(
                            "the update transaction requires boot recovery",
                            &message,
                        ));
                    }
                }
            }

            Ok(TickFlow::Next)
        }
        .await;
        // THE report writer: one per cycle, reached on every path. Reported off the last repository
        // this node resolved, so a cycle that ended early still says what the node is running
        // instead of going silent. `settled` is false while an update is unconfirmed — the
        // confirmation window surfaces as "acted, not yet settled", never as staleness.
        //
        // The two reasons a report is unsettled are reported SEPARATELY: `pending.is_some()` is an
        // update transaction genuinely in flight, while `!last_ready` alone is an ordinary
        // readiness failure with no update anywhere near it. Only this writer can tell them apart,
        // and the control plane's rollback evidence needs the first meaning alone.
        heartbeat
            .emit(
                &opts,
                last_repo.as_ref(),
                &store,
                current.as_deref(),
                Settlement {
                    settled: pending.is_none() && health.last_ready.unwrap_or(false),
                    updating: pending.is_some(),
                },
                fingerprints.current(),
            )
            .await;
        match flow? {
            TickFlow::Next => {}
            TickFlow::Exit => return Ok(()),
        }
    }
}

/// How one cycle of the control loop ended.
enum TickFlow {
    /// Go around again.
    Next,
    /// Leave this supervisor process; the guardian relaunches it.
    Exit,
}

/// The rollout heartbeat's per-process inputs.
///
/// There is exactly one report writer in the supervisor and exactly one call to it — at the end of
/// every cycle, outside the block that does the cycle's work, so no early exit can reach the top of
/// the loop without it. That report is the only thing keeping this node inside `REPORT_FRESHNESS`
/// at the health proxy: a cycle that ends in silence spends the node's freshness budget, and a
/// fault that recurs every cycle (drift that survives a repair, an unconfirmed update) spends it to
/// zero and the node is drained for a reason no reader can see.
struct Heartbeat {
    client: reqwest::Client,
    /// The node identity reports are keyed by; absent on a node with no derivable identity, which
    /// simply never reports.
    node: Option<String>,
    /// The per-node key each report is signed with (PKCS#8 DER).
    signing_key: Option<Vec<u8>>,
}

/// What this node can say about its own settlement on the assignment it is acting on: the two
/// independent facts a report carries, gathered where both are known.
#[derive(Clone, Copy)]
struct Settlement {
    /// The running app is ready AND no update is still unconfirmed.
    settled: bool,
    /// An update transaction is committed and its confirmation window is still open.
    updating: bool,
}

impl Heartbeat {
    /// Write one best-effort report of what this node is running.
    ///
    /// `state.settled` is true only when the running app is ready AND no update is still
    /// unconfirmed — so a node that has merely *fetched* a new assignment, or is mid-rollout, or
    /// was just relaunched onto repaired bytes, is never reported as settled on it. That is what
    /// lets the control plane hold a pair's second member until the first has genuinely completed.
    /// Keyed off the current assignment's report URL, so adding or removing telemetry just starts
    /// or stops the heartbeat.
    ///
    /// `state.updating` is the other half of an unsettled report: an update transaction is
    /// committed and its confirmation window is still open. It is reported rather than inferred
    /// from `settled`, which is also false for a plain readiness failure.
    ///
    /// `repo` is the last repository this node resolved — `None` only before the first successful
    /// resolution, when there is no assignment and so no report target yet.
    async fn emit(
        &self,
        opts: &Options,
        repo: Option<&TrustedRepository>,
        store: &dyn Store,
        version: Option<&str>,
        state: Settlement,
        fingerprint: Option<&updated_contracts::telemetry::Fingerprint>,
    ) {
        let Some(assignment) = repo.and_then(|repo| repo.assignment()) else {
            return;
        };
        let repo = repo.expect("an assignment came from a repository");
        let archive_sha256 = installed_archive_sha256(store);
        let manifest_sha256 = installed_manifest_sha256(store);
        telemetry::report_running_state(
            &self.client,
            assignment.report_url.as_deref(),
            self.node.as_deref(),
            &telemetry::RunningState {
                deployment: &assignment.deployment,
                assignment_sha256: repo.assignment_sha256().unwrap_or_default(),
                version: version.unwrap_or_default(),
                archive_sha256: &archive_sha256,
                healthy: state.settled,
                updating: state.updating,
                fingerprint,
                install_root: &opts.paths.install_root,
                manifest_sha256: &manifest_sha256,
            },
            self.signing_key.as_deref(),
        )
        .await;
    }
}

/// Repair a committed release whose bytes no longer verify on disk (bit rot, a truncated file, a
/// partially restored backup), so local corruption is recoverable instead of a permanent boot
/// crash-loop with the application stopped.
///
/// Two ordered attempts, both driven from signed evidence:
///
///  1. Re-acquire the assigned application from the same signed deployment contract normal updates
///     use. The bundle store republishes a drifted release directory over the verified tree it just
///     expanded, so this restores the ASSIGNED release — the outcome an operator wants — and it is
///     tried first for that reason. For a `file:`/absolute routing repository it makes no network
///     request at all; for every other node it is one repository access, which is exactly what the
///     caller's local verification deliberately runs *in front of*.
///  2. Failing that — an unreachable control plane, an assignment with nothing installable — fall
///     back to the predecessor the committed record already holds for exactly this purpose
///     (`pending.previous_release`, which [`garbage_collect`] keeps on disk). This needs no
///     network at all. Its bytes are verified before the pointer moves, so a second corrupt tree is
///     not launched either, and the update loop converges the node forward again from there.
///
/// The corrupt archive is never *rejected*: a rejection is durable and never expires, and damage to
/// this disk is evidence about this node, not about the release — rejecting it would permanently
/// exclude a perfectly good version from this node and walk its ordered fallback downward.
/// Returns the trusted repository the repair ran off, when it came from the assignment — the caller
/// reports against it without a second refresh. The predecessor fallback below runs precisely when
/// no repository could be loaded, so it has none to give.
async fn repair_committed_bundle(
    opts: &Options,
    store: &mut FileStore,
) -> Result<Option<TrustedRepository>, Box<dyn std::error::Error>> {
    let assignment_error = match repair_from_assignment(opts, store).await {
        Ok(repo) => return Ok(Some(repo)),
        Err(error) => error,
    };
    let Installed::Present(installed) = store.installed() else {
        return Err(assignment_error);
    };
    let Some(pending) = installed.pending else {
        return Err(assignment_error);
    };
    warn(&format!(
        "re-acquiring the assigned application failed ({assignment_error}); falling back to the \
         local predecessor {}",
        pending.previous_release.version
    ));
    // Verify-then-point, and only then commit: a crash between them leaves active on the
    // predecessor with the record still naming the candidate and a `pending` to match, which is the
    // interrupted-rollback shape `plan_boot` already completes on the next boot.
    store.activate(&pending.previous_release).map_err(|error| {
        format!(
            "the local predecessor {} is not intact either: {error}",
            pending.previous_release.version
        )
    })?;
    store.commit_installed(&updated::state::InstalledState::confirmed(
        pending.previous_repository_lineage.clone(),
        pending.previous_release.clone(),
        pending.previous_archive_sha256.clone(),
        pending.lifecycle.clone(),
    ))?;
    log(&format!(
        "repaired the committed application by falling back to the intact predecessor {}",
        pending.previous_release.version
    ));
    Ok(None)
}

/// Re-acquire and re-commit the assigned application from the signed deployment contract. This is
/// the ordinary update machinery's `prepare` step run for repair: the release is re-downloaded and
/// re-materialized, which republishes the drifted tree.
async fn repair_from_assignment(
    opts: &Options,
    store: &mut FileStore,
) -> Result<TrustedRepository, Box<dyn std::error::Error>> {
    let repo = TrustedRepository::assigned(&opts.routing, &opts.storage, &opts.paths)
        .await
        .map_err(|error| format!("loading the signed repair assignment: {error}"))?;
    let assignment = repo
        .assignment()
        .ok_or("the signed repository has no desired deployment")?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    let prepared = crate::acquire::prepare_assigned_application(
        crate::acquire::ApplicationRequest {
            repository: &repo,
            application: &opts.application,
            paths: &opts.paths,
            current_version: None,
        },
        |sha256| store.is_rejected(&lineage, sha256),
    )
    .await
    .map_err(|error| format!("preparing the signed repair: {error}"))?
    .ok_or("the signed assignment contains no installable application")?;
    let providers = selection::stage_providers(opts, &repo, store, None)
        .await
        .map_err(|error| format!("staging the providers for the repair: {error}"))?;
    // A repair replaces drifted BYTES; it does not decide an in-flight update. When it lands back
    // on the release the record already names, the record's rollback intent and its provisional
    // flag are carried through unchanged: erasing them would silently confirm an unconfirmed head —
    // nothing left for `plan_boot` to revert on the next crash, and `garbage_collect` free to prune
    // the very predecessor this function's own fallback depends on. A repair that lands on a
    // different head (the assignment moved on) is a head this node has never launched, let alone
    // health-gated, so it is committed provisional exactly as a cold install commits one — ordered
    // fallback has to be able to descend past it if it turns out to be broken.
    let (pending, confirmed) = match store.installed() {
        Installed::Present(state) if state.release == prepared.release => {
            (state.pending, state.confirmed)
        }
        _ => (None, false),
    };
    // Verify-then-point, and only then commit — the same order, and for the same reason, as the
    // predecessor fallback in `repair_committed_bundle`: a failed `activate` (ENOSPC, a read-only
    // remount) must leave the committed record exactly as it found it, so the fallback still has
    // the `pending` it reads to recover.
    store.activate(&prepared.release)?;
    store.commit_installed(&updated::state::InstalledState {
        repository_lineage: lineage,
        release: prepared.release.clone(),
        archive_sha256: prepared.archive_sha256,
        lifecycle: Box::new(providers),
        pending,
        confirmed,
    })?;
    // Wording held stable: the e2e's offline-repair scenario asserts on this exact line, and the
    // scenario it covers — a `file:` routing repository, no network — is the one it names.
    log(&format!(
        "repaired the committed application from signed local deployment {}",
        prepared.version
    ));
    Ok(repo)
}

/// End this supervisor because it cannot make progress, leaving every piece of durable evidence
/// (the transaction journal, the unspent marker claims, the rejection records) exactly as it is.
///
/// This is the ONLY response to an unrecoverable boot or update step, and it is deliberately an
/// exit rather than a wait: the agent is disposable — it holds no workload — and the launcher
/// relaunches it, so the next boot re-derives the identical, idempotent recovery from the same
/// evidence. Holding the process alive instead means a single failed durable write pins the node
/// down forever: no exit, so no relaunch, so no next boot, so the recovery that was supposed to
/// happen "next boot" never did. Replaying an operator hook in
/// a tight loop is not the alternative hazard it looks like either: the launcher throttles every
/// relaunch through one exponential backoff capped at five minutes, and that backoff is rate-
/// limited precisely so THIS path cannot escape it. An exit from here typically comes after a long
/// boot — situation gathering, activation, an operator hook with an operator-chosen timeout — so
/// the launcher's "it ran a while, this was a transient crash" reset would otherwise
/// fire on every cycle; it stops resetting past a bounded number of relaunches per hour, and the
/// loop settles at one replay per five minutes.
fn exit_for_relaunch(what: &str, cause: &dyn std::fmt::Display) -> Box<dyn std::error::Error> {
    let reason = format!(
        "{what} failed: {cause}; exiting with the recovery journal intact so the guardian \
         relaunches boot recovery"
    );
    error(&reason);
    reason.into()
}

/// How long a boot-recovery step is retried when what failed it is a node-local transient, and
/// how long it waits between attempts.
struct TransientRetry {
    budget: Duration,
    interval: Duration,
}

impl TransientRetry {
    /// The budget boot recovery runs with. It must outlast the guardian's readiness gate plus its
    /// confirmation window (45s + 30s with the shipped defaults), because that is the whole point:
    /// a candidate that spends the transient behind its readiness signal gets COMMITTED, so if the
    /// fault outlives the budget the exit that follows is an ordinary relaunch instead of a
    /// permanent, by-content-hash rejection.
    const BOOT: TransientRetry = TransientRetry {
        budget: Duration::from_secs(120),
        interval: Duration::from_secs(3),
    };
}

/// Run one fallible boot-recovery step, waiting out node-local transients from behind the
/// readiness signal, and turning anything else into [`exit_for_relaunch`].
///
/// Boot recovery runs in front of the readiness signal because commitment is meant to attest that
/// these supervisor bytes reconciled their durable state. But for a CANDIDATE supervisor, exiting
/// before that signal is not the relaunch `exit_for_relaunch` describes — the guardian records the
/// candidate rejected, the predecessor comes back and blacklists the candidate's SHA-256 in
/// `supervisor-rejected`, a record that never expires. A full state volume, a read-only remount, an
/// EIO, or a CDN blip during staging would therefore strand this node a supervisor release behind
/// the fleet, permanently, over a fault that says nothing about the release — the same fault
/// attribution `update.rs` already makes for a pointer write and `self_update.rs` for a failed
/// handoff.
///
/// So a transient cause is retried instead, and readiness is signalled before the first retry:
/// with the signal sent, the confirmation window runs on its own clock and the candidate is
/// committed on the strength of what it is — bytes that started and stayed up — rather than on
/// whether this node's disk was writable at that moment. Retrying is safe because the step is
/// exactly what the next boot would re-derive: every phase is guarded by `recovery_pending`, so a
/// re-run resumes where the failure landed.
///
/// The retry is BOUNDED. A supervisor that never exits is the failure mode `exit_for_relaunch`
/// exists to prevent, so once the budget is spent this ends the process like any other
/// unrecoverable step — by then the candidate is committed, and the relaunch is throttled by the
/// guardian's backoff.
async fn recover_through_transients<T>(
    what: &str,
    retry: &TransientRetry,
    guardian: &mut Guardian,
    shutdown: &AtomicBool,
    mut step: impl FnMut() -> io::Result<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + retry.budget;
    loop {
        let error = match step() {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !retry_after_transient(&error, Instant::now(), deadline, shutdown) {
            return Err(exit_for_relaunch(what, &error));
        }
        warn(&format!(
            "{what} hit a node-local fault ({error}); signalling readiness and retrying in {}ms so \
             a transient cannot get these supervisor bytes rejected by content hash",
            retry.interval.as_millis()
        ));
        // Idempotent: the ordinary signal below this in `run` still happens, and only one READY
        // frame reaches the guardian.
        guardian.signal_ready();
        if sleep_interruptible(retry.interval, shutdown).await {
            return Err(exit_for_relaunch(what, &error));
        }
    }
}

/// Whether a failed recovery step earns another attempt from behind the readiness signal: only a
/// node-local transient, only while the budget lasts, and never once a stop was requested. Anything
/// else is the release's own fault (or out of time) and takes the [`exit_for_relaunch`] path.
fn retry_after_transient(
    error: &io::Error,
    now: Instant,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> bool {
    is_node_local_transient(error) && now < deadline && !shutdown.load(Ordering::SeqCst)
}

/// Whether an I/O failure is a fault of the NODE — its disk, its filesystem, its network — rather
/// than of the release or the state being reconciled. These are the causes that clear on their own
/// and say nothing about the bytes that hit them; every other kind (corrupt data, a bad path, an
/// invalid transition) is owned by whatever produced it.
fn is_node_local_transient(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::StorageFull
            | io::ErrorKind::QuotaExceeded
            | io::ErrorKind::ReadOnlyFilesystem
            | io::ErrorKind::ResourceBusy
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    ) {
        return true;
    }
    // A hardware/transport read or write error has no `ErrorKind` of its own — it arrives
    // `Uncategorized`, which is not matchable — so it is recognised by its raw code. A post-commit
    // fsync failure arrives wrapped by `foundation::durable` ("the change landed but is not proved
    // durable"), and an `io::Error` carrying that payload cannot ALSO carry a raw code — `Os` and
    // `Custom` are alternative representations — so for those the code lives one `source` hop down,
    // which `foundation::durable` documents and pins with a regression test.
    #[cfg(unix)]
    {
        if error.raw_os_error() == Some(libc::EIO) {
            return true;
        }
        let mut source = std::error::Error::source(error);
        while let Some(current) = source {
            if current
                .downcast_ref::<io::Error>()
                .is_some_and(|cause| cause.raw_os_error() == Some(libc::EIO))
            {
                return true;
            }
            source = current.source();
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
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
    // A release's writable working directory lives outside its content-addressed tree — the tree is
    // re-hashed on every check, so an application writing to its own `cwd` would condemn it — which
    // means pruning the tree does not take the scratch with it. Reap here, in the same pass, rather
    // than leaving it to whenever the node next resolves a release for launch.
    updated::gc::reap_orphaned_workspaces(&opts.paths.work, &opts.paths.versions);
    updated::gc::reap_orphaned_workspaces(&opts.paths.provider_work, &opts.paths.provider_versions);
}

/// Reject the bytes of a *provisional* (never-health-proven) cold-installed head so the next
/// boot's cold install descends via ordered fallback past it.
///
/// Called only for a head [`boot::plan_gate_failure`] has already classified provisional: a head
/// with a predecessor to revert to takes the revert path instead, and a confirmed head is never
/// rejected for ill health at all.
fn reject_provisional_head(
    store: &mut FileStore,
    state: &updated::state::InstalledState,
) -> std::io::Result<()> {
    store.reject(&state.repository_lineage, &state.archive_sha256)?;
    warn(&format!(
        "provisional head {} never passed a health gate; rejected its bytes so the next cold \
         install descends via ordered fallback",
        state.release.version
    ));
    Ok(())
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
        return match boot::journal_recovery(tx, situation.active.as_ref(), committed) {
            // The predecessor must actually be restored: this journal IS the recovery, and it is
            // resumed from its own recorded phase.
            updated::transaction::Recovery::RestorePredecessor => Some(tx.clone()),
            // The update's commit landed, so this journal has nothing left to undo — it is merely
            // spent (a tolerated `clear_journal` failure, or a crash between the commit and the
            // journal's terminal write) — including when the active pointer has since moved off the
            // candidate, which [`boot::journal_recovery`] resolves rather than mistaking a spent
            // journal for a rollback it can never drive. What matters now is the same thing with no
            // journal at all: the boot plan treats the committed record's `pending` as
            // authoritative, so this boot may still be a confirmation-window revert. Derive that
            // rollback from `pending` exactly as the journal-less path does — the candidate's
            // machine-state changes are owed a compensating `rollback` either way, and a spent
            // file on disk must not be what decides whether they are undone.
            updated::transaction::Recovery::Committed => confirmation_window_rollback(situation),
            // Nothing was ever displaced (a pre-activation crash), or the rollback already ran to
            // completion. `reconcile_transaction` clears the journal and, for a finished rollback,
            // commits the predecessor with zero lifecycle calls; synthesizing anything here would
            // re-run an already-completed rollback machine and double-invoke every hook.
            updated::transaction::Recovery::NeverSwapped => None,
        };
    }
    confirmation_window_rollback(situation)
}

/// The rollback owed by the committed record itself, when a previous boot already moved the active
/// pointer back to `pending.previous_release` but died before the compensating `rollback` and the
/// final commit. It is the revert [`boot::plan_boot`] completes off `pending`, and it must replay
/// the operator's `rollback` for the candidate's machine-state changes.
///
/// The rejection is NOT re-derived here: the boot that judged the candidate recorded it durably
/// (see [`revert_unconfirmed_head`]) before the pointer ever moved.
fn confirmation_window_rollback(situation: &Situation) -> Option<Transaction> {
    let Installed::Present(installed) = &situation.installed else {
        return None;
    };
    let pending = installed.pending.as_ref()?;
    if situation.active.as_ref() != Some(&pending.previous_release) {
        return None;
    }
    Some(rollback_of_unconfirmed(installed, pending, false))
}

/// The rollback transaction that reverts `installed` to the predecessor its `pending` names — the
/// one shape both the boot gate's revert and the resumption of an interrupted one produce, so a
/// revert that is decided in one boot and driven by the next cannot describe two different things.
fn rollback_of_unconfirmed(
    installed: &updated::state::InstalledState,
    pending: &Pending,
    reject_candidate: bool,
) -> Transaction {
    Transaction {
        id: pending.lifecycle_attempt_id.clone(),
        previous_release: pending.previous_release.clone(),
        previous_archive_sha256: pending.previous_archive_sha256.clone(),
        previous_repository_lineage: pending.previous_repository_lineage.clone(),
        candidate_release: installed.release.clone(),
        candidate_archive_sha256: installed.archive_sha256.clone(),
        candidate_repository_lineage: installed.repository_lineage.clone(),
        candidate_rejection_required: reject_candidate,
        lifecycle: pending.lifecycle.clone(),
        rollback_health_failures: 0,
        phase: TransactionPhase::RollbackStarted,
    }
}

/// Record the revert an unconfirmed release earned by failing its boot health gate: a durable
/// rollback journal, and the candidate's rejection.
///
/// Only the intent is written here — the rollback itself is boot recovery's, the single
/// implementation — so this agent exits and the next boot restores the predecessor's pointer, runs
/// its `apply`, gates it, and replays the compensating `rollback` from exactly this journal.
///
/// `bytes_repaired` is the one thing that withholds the rejection. It is permanent and keyed by
/// archive hash, so it may never be charged to bytes this same boot re-downloaded and re-verified:
/// the gate then failed on a tree that no longer exists. The revert is owed either way — it is
/// reversible — and a release that fails the gate again on the next boot, which finds the tree
/// intact, is charged for it, so the descent still terminates.
fn revert_unconfirmed_head(
    store: &mut dyn Store,
    installed: &updated::state::InstalledState,
    bytes_repaired: bool,
) -> io::Result<()> {
    let pending = installed
        .pending
        .as_ref()
        .expect("an unconfirmed head has a pending record");
    let tx = rollback_of_unconfirmed(installed, pending, !bytes_repaired);
    warn(&format!(
        "release {} failed its boot health gate inside its confirmation window; reverting to {}",
        installed.release.version, pending.previous_release.version
    ));
    persist_transaction(store, &tx)?;
    if tx.candidate_rejection_required {
        store.reject(&installed.repository_lineage, &installed.archive_sha256)?;
    }
    Ok(())
}

fn complete_recovery_activation(
    opts: &Options,
    store: &mut dyn Store,
    recovery: Option<&mut Transaction>,
) -> io::Result<()> {
    let Some(tx) = recovery else {
        return Ok(());
    };
    if !tx.recovery_pending(TransactionPhase::PredecessorActivated) {
        return Ok(());
    }
    // Restore the predecessor's machine state through the same reconciler operation used for the
    // candidate — the predecessor's own `apply`, which is what re-converges whatever it owns.
    run_lifecycle_command(
        tx.lifecycle.as_ref(),
        opts,
        LifecycleInvocation {
            phase: Operation::Apply,
            reason: LifecycleReason::Update,
            id: &tx.id,
            candidate: &tx.previous_release,
            predecessor: &tx.candidate_release,
        },
    )?;
    Chaos::from_env().crossing(update::boundary::PREDECESSOR_LIFECYCLE_APPLIED);
    advance_transaction(store, tx, TransactionPhase::PredecessorActivated)
}

// ============================== boot: gather + execute ==============================

/// Read the whole world the boot planner needs — durable state via the [`Store`] and the
/// launcher's rejection marker, already claimed into [`guardian::Evidence`] — into one
/// [`Situation`]. The shell's single point of input gathering. Reading evidence leaves it on disk;
/// the boot path clears the claim only once the intent it implies is durable.
fn gather_situation(
    opts: &Options,
    store: &dyn Store,
    evidence: &guardian::Evidence,
) -> io::Result<Situation> {
    let active = store.active_release()?;
    let installed = store.installed();
    let journal = store.journal()?;
    Ok(Situation {
        installed,
        active,
        journal,
        bad_supervisor: evidence.rejected_supervisor().map(PathBuf::from),
        confirm_window: opts.timeouts.confirmation_window,
        now: now_unix(),
    })
}

/// Perform a boot [`Plan`]'s durable reconciliation and return the still-unconfirmed
/// update (if any) for the loop to watch.
fn execute_boot_plan(
    plan: &Plan,
    store: &mut dyn Store,
    self_update: &mut SelfUpdateState,
    defer_commit: bool,
    mut recovery: Option<&mut Transaction>,
    evidence: &mut guardian::Evidence,
) -> io::Result<Option<Pending>> {
    if let Some(tx) = recovery.as_mut() {
        if tx.recovery_pending(TransactionPhase::RollbackActivateStarted) {
            advance_transaction(store, tx, TransactionPhase::RollbackActivateStarted)?;
        }
    }
    let activate_release = recovery
        .as_ref()
        .is_none_or(|tx| tx.recovery_pending(TransactionPhase::PredecessorActivated));
    apply_store_plan(plan, store, defer_commit, activate_release)?;
    if activate_release && !matches!(plan.release, ReleaseFix::None) {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_POINTER_APPLIED);
    }
    if let Some(path) = &plan.reject_supervisor {
        // Fallible on purpose, and cleared only here: a rejection that failed to reach disk must
        // not be mistaken for a durable one. If the write fails this boot fails with the marker
        // intact, so the next boot rejects the same candidate instead of re-staging it forever.
        //
        // With one exception, which is the marker module's own stated invariant: bytes that are not
        // a content-addressed `supervisors/<hash>/<binary>` path — a stray write, a truncated or
        // partially restored file — name no hash to suppress and are not evidence about any
        // candidate. Failing the boot on them would fail identically on every subsequent boot (the
        // marker is only ever cleared here), leaving the node permanently unbootable, so they are
        // discarded with a warning and the marker is cleared.
        //
        // The shape is decided HERE, before the write is attempted, and `reject_candidate` takes
        // the extracted hash rather than re-deriving it: a failing write reports `InvalidInput`
        // for a bad key too, so classifying the error afterwards would make "malformed marker"
        // and "the rejection did not reach disk" the same test.
        if let Some(hash) = rejected_supervisor_hash(path) {
            self_update.reject_candidate(hash)?;
        } else {
            warn(&format!(
                "discarding an unusable rejected-supervisor marker: {} is not a content-addressed \
                 supervisors/<hash>/<binary> path and names no candidate to suppress",
                path.display()
            ));
        }
        evidence.clear_rejected_supervisor()?;
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

/// The candidate hash a rejected-supervisor marker names, or `None` when the marker's bytes are
/// not a content-addressed `supervisors/<hash>/<binary>` path.
///
/// The one place that extraction happens; the hash it yields is what `reject_candidate` records.
/// It applies the very predicate `Rejections::reject` validates with — [`updated::reject::is_rejection_key`],
/// called rather than restated — so this accepts exactly the markers that path would accept
/// however that grammar moves. Every marker it turns down would have failed there with no hash
/// recorded anyway.
fn rejected_supervisor_hash(path: &std::path::Path) -> Option<&str> {
    let hash = path.parent()?.file_name()?.to_str()?;
    updated::reject::is_rejection_key(hash).then_some(hash)
}

/// The unconfirmed update recorded in the installed state, if any.
fn installed_pending(store: &dyn Store) -> Option<Pending> {
    match store.installed() {
        Installed::Present(s) => s.pending,
        _ => None,
    }
}

/// The SHA-256 of the archive the committed head was installed from, for the rollout heartbeat.
/// Read from the store at report time rather than tracked alongside the running version: the
/// version is a local carried across four separate commit paths, and a digest that drifted out of
/// step with it would name bytes that are not running — worse than naming none. Empty when nothing
/// is committed (no install yet, or an unreadable record), reported as "running no known bytes".
fn installed_archive_sha256(store: &dyn Store) -> String {
    match store.installed() {
        Installed::Present(state) => state.archive_sha256,
        _ => String::new(),
    }
}

fn installed_manifest_sha256(store: &dyn Store) -> String {
    match store.installed() {
        Installed::Present(state) => state.release.manifest_sha256,
        _ => String::new(),
    }
}

/// Run one steady-state probe against the committed release and the lifecycle provider that must
/// invoke it, read together from the one installed record.
///
/// The record is read here, inside the call, and `probe` only ever *borrows* what it names — so a
/// caller cannot hold a target across ticks without deliberately cloning one, and the shape the
/// loop used to have (resolve once at boot, reuse forever) does not compile. That matters because
/// `garbage_collect` protects exactly the provider release this record names, so any second copy of
/// it is a release the collector is free to prune: an in-loop repair commits a different provider
/// (its own `stage_providers` result), the boot-time copy then named a provider bundle that was
/// about to disappear, and every periodic probe after it failed to resolve — so a node whose
/// release was serving perfectly well reported itself unready and was drained out of rotation.
fn probe_steady_target<T>(
    store: &dyn Store,
    probe: impl FnOnce(&updated::bundle::ReleaseId, &updated::state::ProviderRelease) -> T,
) -> io::Result<T> {
    match store.installed() {
        Installed::Present(state) => Ok(probe(&state.release, &state.lifecycle)),
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

/// What one wake of the control loop owes, decided before any work is done.
///
/// A pending confirmation suppresses the update *check*, never the cycle. The cycle ends in the
/// node's only report, and a node that goes silent for the whole confirmation window is drained out
/// of load-balancer rotation immediately after every successful update — read as stale rather than
/// as "acted, not yet settled", which is the distinction `settled` exists to publish.
#[derive(Debug, PartialEq, Eq)]
struct Cycle {
    /// The cycle clock fired: refresh the repository, reconcile the assignment, and report.
    due: bool,
    /// This cycle may also start a new application update. False while an update is unconfirmed:
    /// one rollout step at a time.
    updates: bool,
}

fn cycle_due(pending: bool, now: Instant, next_check: Instant) -> Cycle {
    let due = now >= next_check;
    Cycle {
        due,
        updates: due && !pending,
    }
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
    use crate::store::MemStore;
    use updated::bundle::ReleaseId;
    use updated::state::{Installed, InstalledState, RepositoryLineage};
    use updated::transaction::Phase;

    fn release(version: &str, digest: &str) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    /// One loop tick's steady-state probe, recording exactly what it was lent.
    fn tick(store: &dyn Store) -> (ReleaseId, Box<updated::state::ProviderRelease>) {
        probe_steady_target(store, |installed, lifecycle| {
            (installed.clone(), Box::new(lifecycle.clone()))
        })
        .expect("an installed record")
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
    fn an_unrecoverable_boot_step_ends_the_process_instead_of_holding_the_node_down() {
        // Regression: every one of these used to route into an infinite `while !shutdown { sleep }`
        // hold. A single failed durable write — ENOSPC recording a rejection, a read-only remount —
        // then meant the supervisor never exited, so the guardian never relaunched it, so the "next
        // boot" that was supposed to redo the recovery never happened, with the node serving
        // nothing. The only correct answer is to end the process and let the guardian (which
        // throttles relaunches through one capped backoff) start the next boot.
        let cause = io::Error::new(io::ErrorKind::StorageFull, "no space left on device");
        let error = exit_for_relaunch("recording the candidate's rejection", &cause);
        let message = error.to_string();
        assert!(message.contains("no space left on device"), "{message}");
        assert!(
            message.contains("relaunches boot recovery"),
            "the operator is told what happens next: {message}"
        );
    }

    #[test]
    fn the_steady_probe_is_handed_the_provider_the_record_names_at_that_tick() {
        // Two ticks of the health-probe loop with an in-loop repair between them, driven through
        // the same call the loop makes. The repair commits a release AND a provider set of its own,
        // and `garbage_collect` protects only what the installed record names — so a provider
        // resolved once at boot named a bundle the very next collection was free to prune, after
        // which every periodic probe failed to resolve its command and the third one called
        // `application_failed`, terminal, on a tower that was serving fine.
        //
        // The re-read is now structural rather than a convention this test could only watch: the
        // target is *lent* to the probe for the length of one call, so hoisting it back out of the
        // loop cannot compile without a deliberate clone.
        let lineage = RepositoryLineage::from_metadata_url("https://repo/metadata/");
        let mut damaged = provider();
        damaged.release = release("1.0.0", "damaged-provider-manifest");
        let mut store = MemStore {
            installed: Some(InstalledState::confirmed(
                lineage.clone(),
                release("1.0.0", "damaged"),
                "archive-damaged".into(),
                damaged.clone(),
            )),
            ..MemStore::default()
        };
        let at_boot = tick(&store);
        assert_eq!(at_boot, (release("1.0.0", "damaged"), damaged));

        let repaired = release("1.0.1", "repaired");
        store
            .commit_installed(&InstalledState::confirmed(
                lineage,
                repaired.clone(),
                "archive-repaired".into(),
                provider(),
            ))
            .unwrap();

        let after_repair = tick(&store);
        assert_eq!(
            after_repair,
            (repaired, provider()),
            "each tick probes the provider its own record names, not the one named at boot"
        );
        // The collector derives its protected set from that same record, so probe and collector
        // cannot name different provider releases.
        match store.installed() {
            Installed::Present(state) => assert_eq!(state.lifecycle, after_repair.1),
            _ => panic!("expected the repaired record"),
        }
    }

    /// A node whose update committed (installed = candidate, pending = predecessor) and whose
    /// revert a previous boot began — the active pointer is already back on the predecessor — with
    /// `journal` still on disk in the given phase.
    fn interrupted_revert(phase: Option<Phase>) -> Situation {
        let lineage = RepositoryLineage::from_metadata_url("https://repo/metadata/");
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let installed = InstalledState {
            repository_lineage: lineage.clone(),
            release: candidate.clone(),
            archive_sha256: "archive-two".into(),
            lifecycle: provider(),
            pending: Some(updated::state::Pending {
                lifecycle_attempt_id: "attempt".into(),
                previous_release: predecessor.clone(),
                previous_archive_sha256: "archive-one".into(),
                previous_repository_lineage: lineage.clone(),
                committed_at: 100,
                lifecycle: provider(),
            }),
            confirmed: true,
        };
        Situation {
            installed: Installed::Present(Box::new(installed)),
            active: Some(predecessor.clone()),
            journal: phase.map(|phase| Transaction {
                id: "attempt".into(),
                previous_release: predecessor,
                previous_archive_sha256: "archive-one".into(),
                previous_repository_lineage: lineage.clone(),
                candidate_release: candidate,
                candidate_archive_sha256: "archive-two".into(),
                candidate_repository_lineage: lineage,
                candidate_rejection_required: false,
                lifecycle: provider(),
                rollback_health_failures: 0,
                phase,
            }),
            bad_supervisor: None,
            confirm_window: Duration::from_secs(60),
            now: 120,
        }
    }

    #[test]
    fn an_unconfirmed_update_still_owes_a_report() {
        // The regression. A cycle is due on its own clock; a pending confirmation withholds only
        // the update check inside it. Suppressing the whole cycle silenced the node for the entire
        // confirmation window — twice REPORT_FRESHNESS with the shipped defaults — right after
        // every successful update, so the health proxy drained the node it had just upgraded and
        // the rollout throttle read "stale" where the truth was "acted, not yet settled".
        let now = Instant::now();
        assert_eq!(
            cycle_due(true, now, now),
            Cycle {
                due: true,
                updates: false
            },
            "a pending confirmation withholds the update check, never the cycle or its report"
        );
        assert_eq!(
            cycle_due(false, now, now),
            Cycle {
                due: true,
                updates: true
            }
        );
        let later = now + Duration::from_secs(1);
        assert_eq!(
            cycle_due(false, now, later),
            Cycle {
                due: false,
                updates: false
            },
            "before the clock fires nothing is owed"
        );
    }

    #[test]
    fn the_cycle_has_exactly_one_report_writer_and_no_way_around_it() {
        // The node's report freshness is what keeps it in rotation, and the loop has exactly ONE
        // report writer. Several paths end a cycle early (a failed refresh, a converge, an
        // integrity repair under drift that survives it); each one that reached the top of the loop
        // without reporting spent the node's freshness budget and drained it one REPORT_FRESHNESS
        // later, for a reason no reader could see. The structure that makes that impossible is the
        // cycle body being an expression whose early exits leave the block, not the tick, with the
        // single emit after it — so this asserts the structure, which is the invariant.
        let source = include_str!("main.rs");
        let emitter = concat!("telemetry::report_", "running_state(");
        assert_eq!(
            source.matches(emitter).count(),
            1,
            "reports must have exactly one writer"
        );
        assert_eq!(
            source.matches("heartbeat\n            .emit(").count(),
            1,
            "and exactly one call site, at the end of the cycle"
        );
        let block = source
            .find("let flow: Result<TickFlow")
            .expect("the cycle body is one expression");
        let tail = &source[block..];
        let emit = tail.find(".emit(").expect("the cycle ends in a report");
        assert!(
            !tail[..emit].contains("\n            continue;")
                && !tail[..emit].contains("\n        continue;"),
            "nothing inside the cycle body may reach the top of the loop; early exits return TickFlow"
        );
    }

    /// The committed record of an unconfirmed update, as the boot health gate finds it.
    fn unconfirmed_head() -> InstalledState {
        let lineage = RepositoryLineage::from_metadata_url("https://repo/metadata/");
        InstalledState {
            repository_lineage: lineage.clone(),
            release: release("2.0.0", "two"),
            archive_sha256: "archive-two".into(),
            lifecycle: provider(),
            pending: Some(updated::state::Pending {
                lifecycle_attempt_id: "attempt".into(),
                previous_release: release("1.0.0", "one"),
                previous_archive_sha256: "archive-one".into(),
                previous_repository_lineage: lineage,
                committed_at: 100,
                lifecycle: provider(),
            }),
            confirmed: true,
        }
    }

    fn store_holding(installed: &InstalledState) -> MemStore {
        MemStore {
            installed: Some(installed.clone()),
            active: Some(installed.release.clone()),
            ..MemStore::default()
        }
    }

    #[test]
    fn a_failed_gate_inside_the_window_records_a_drivable_revert_and_the_rejection() {
        // The one local revert left in the agent, at its decision point: the release's
        // `healthcheck` would not pass at boot while the update was still unconfirmed, so the
        // candidate is rejected by content hash and a rollback journal is left for the next boot —
        // the single rollback implementation. Recording the intent rather than performing it here
        // is what keeps that true.
        let head = unconfirmed_head();
        let mut store = store_holding(&head);

        revert_unconfirmed_head(&mut store, &head, false).unwrap();

        let journal = store.journal().unwrap().expect("a durable rollback intent");
        assert!(journal.is_rollback());
        assert_eq!(journal.previous_release, release("1.0.0", "one"));
        assert!(journal.candidate_rejection_required);
        assert!(journal.recovery_pending(Phase::PredecessorActivated));
        assert!(journal.recovery_pending(Phase::RolledBack));
        assert!(store.is_rejected(&head.repository_lineage, "archive-two"));
    }

    #[test]
    fn a_repaired_boot_still_owes_the_revert_but_not_the_rejection() {
        // A rejection is permanent and keyed by archive hash, so it may never be charged to bytes
        // this same boot re-downloaded and re-verified — the gate failed on a tree that no longer
        // exists. The revert is owed either way: it is reversible, and the next boot finds an
        // intact tree and charges a repeat failure to the release.
        let head = unconfirmed_head();
        let mut store = store_holding(&head);

        revert_unconfirmed_head(&mut store, &head, true).unwrap();

        let journal = store.journal().unwrap().expect("the revert is still owed");
        assert!(journal.is_rollback());
        assert!(!journal.candidate_rejection_required);
        assert!(
            !store.is_rejected(&head.repository_lineage, "archive-two"),
            "the repair re-verified these bytes; they must not be blacklisted"
        );
    }

    #[test]
    fn a_confirmed_release_that_fails_its_gate_is_only_reported() {
        // The other half of the policy: a release that has proven itself once is never reverted
        // locally on a later unhealthy gate. The reconciler owns the workload and may converge it,
        // there is no predecessor image left, and reverting would fight the assignment — so it is
        // reported unhealthy and the agent keeps reconciling.
        let confirmed = InstalledState::confirmed(
            RepositoryLineage::from_metadata_url("https://repo/metadata/"),
            release("2.0.0", "two"),
            "archive-two".into(),
            provider(),
        );
        assert_eq!(boot::plan_gate_failure(&confirmed), GateFailure::Report);
        assert_eq!(
            boot::plan_gate_failure(&unconfirmed_head()),
            GateFailure::Revert
        );
        // Whichever way the gate went, it is this boot's first observation and the node's first
        // report carries it.
        let timeouts = Timeouts::default();
        assert_eq!(
            HealthWatch::after_boot_gate(&timeouts, false).last_ready,
            Some(false)
        );
        assert_eq!(
            HealthWatch::after_boot_gate(&timeouts, true).last_ready,
            Some(true)
        );
    }

    #[test]
    fn a_spent_journal_still_derives_a_drivable_revert() {
        // Regression: `switch_over` tolerates a failed `clear_journal`, and an agent can die
        // between `commit_installed` and the journal's terminal write — either way a spent
        // CommitStarted/Committed journal survives. A later boot then finds the pointer already
        // back on the predecessor (the revert a failed gate began). `classify_recovery` reads
        // `RestorePredecessor`, but the phase machine refuses to BEGIN a rollback from a terminal
        // `Committed`, so returning that journal verbatim produced a "recovery" with no rollback
        // rank: every resume gate closed, the plan's reconciliation was silently discarded, and
        // the candidate's machine-state changes were never compensated.
        for phase in [Phase::CommitStarted, Phase::Committed] {
            let mut tx = recovery_transaction(&interrupted_revert(Some(phase)))
                .unwrap_or_else(|| panic!("a spent {phase:?} journal still owes the revert"));
            if !tx.is_rollback() {
                tx.advance(Phase::RollbackStarted)
                    .expect("a non-terminal journal is moved onto the rollback path");
            }
            assert_eq!(tx.previous_release, release("1.0.0", "one"));
            assert!(tx.recovery_pending(Phase::PredecessorActivated));
            assert!(tx.recovery_pending(Phase::RolledBack));
        }
    }

    #[test]
    fn a_journal_with_a_finished_rollback_is_not_re_run() {
        // Guard the scope of the fix: `NeverSwapped` (here, a completed rollback whose pointer is
        // back on the predecessor) is handled by the boot plan alone, and synthesizing anything
        // from `pending` would re-run the whole rollback machine and double-invoke every hook.
        assert!(recovery_transaction(&interrupted_revert(Some(Phase::RolledBack))).is_none());
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

    /// The shipped example values from the finding this test pins: a 30s start grace with a 1s
    /// probe interval. A converge the loop performs itself gets that whole grace, or the fourth
    /// second after a benign reassignment reports a still-starting release as unready.
    fn reassignment_timeouts() -> Timeouts {
        Timeouts {
            health_grace: Duration::from_secs(30),
            health_interval: Duration::from_secs(1),
            ..Timeouts::default()
        }
    }

    #[test]
    fn a_converge_arms_the_configured_start_grace_before_the_first_probe() {
        let timeouts = reassignment_timeouts();
        let mut health = HealthWatch::after_boot_gate(&timeouts, true);
        assert!(
            health.next_probe <= Instant::now() + timeouts.health_interval,
            "a release the boot gate just proved is probed one interval later"
        );

        // The control plane publishes a reassignment that changes only the runtime; the loop runs
        // `apply --reason restart` and the reconciler brings the workload back up on its own time.
        let converged_at = Instant::now();
        health.reconverged(&timeouts);
        assert!(
            health.next_probe >= converged_at + timeouts.health_grace,
            "nothing has proven the re-applied release, so no probe may be recorded against it \
             until the configured grace has passed"
        );
        assert_eq!(
            health.last_ready, None,
            "the previous release's readiness is not the re-applied release's readiness"
        );
    }

    #[test]
    fn an_unhealthy_steady_probe_is_reported_and_never_acted_on() {
        // Health is the reconciler's answer about a workload this agent does not own, so a
        // periodic probe only ever moves what the node REPORTS. Past the confirmation window there
        // is no local response to ill health at all — the control plane decides.
        let timeouts = reassignment_timeouts();
        let mut health = HealthWatch::after_boot_gate(&timeouts, true);
        let mut now = Instant::now();
        for _ in 0..10 {
            health.observed(now, false, &timeouts);
            assert_eq!(health.last_ready, Some(false));
            now += timeouts.health_interval;
        }
        health.observed(now, true, &timeouts);
        assert_eq!(
            health.last_ready,
            Some(true),
            "a release the hook brings back reports ready again with no agent intervention"
        );
        assert_eq!(health.next_probe, now + timeouts.health_interval);
    }

    /// Options in the shape [`crate::options::parse_args`] produces, against a local routing
    /// repository so nothing here reaches the network.
    fn options() -> Options {
        use updated::config::{Paths, Routing, Storage};
        let root = PathBuf::from("/nonexistent/updated-agent-tests");
        let routing = Routing {
            root: root.join("enrollment/routing"),
            base_url: root.join("routing").display().to_string(),
            assignment: "assignments/agents/agent-test.json".into(),
            transport_timeout: Duration::from_secs(30),
            mtls: updated::tls::Identity::new(
                root.join("client.pem"),
                root.join("client.key"),
                root.join("ca.pem"),
            ),
        };
        Options {
            deployment: "test".into(),
            secrets: crate::secrets::SecretManager::new(&routing, &[]).expect("a local repository"),
            paths: Paths::resolve(&root, &root.join("enrollment")),
            application: Application {
                product: "app".into(),
                channel: "stable".into(),
                install_root: root.clone(),
                secrets: Vec::new(),
                inputs: std::collections::BTreeMap::new(),
            },
            routing,
            timeouts: BoundedTimeouts::new(Timeouts::default()),
            storage: Storage::default(),
            supervisor_update: SupervisorUpdate {
                channel: "stable".into(),
                state_dir: root.join("state"),
                check_interval: Duration::from_secs(60),
            },
            identity_renewal: IdentityRenewal {
                bootstrap: root.join("bootstrap.toml"),
                state_dir: root.join("enrollment"),
            },
        }
    }

    fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        use updated_contracts::assignment::{
            ManagedRepositoryLimits, ManagedRuntime, ManagedStorage, ManagedTimeouts,
        };
        ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: PathBuf::from("/nonexistent/updated-agent-tests"),
            secrets: Vec::new(),
            inputs: std::collections::BTreeMap::new(),
            repository: ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 30,
            },
            storage: ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1 << 30,
                inactive_repository_caches: 2,
            },
            timeouts: ManagedTimeouts {
                check_interval_seconds: 15,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
            },
        }
    }

    #[test]
    fn a_reassignment_converges_exactly_when_the_release_could_observe_the_change() {
        // The agent owns no process to reconfigure, so the ONLY way a changed secret reference or
        // a re-resolved input reaches the release is another reconciler invocation — its
        // environment and its `--input-file`. Answering "no change" on one of those leaves the
        // node running on values the assignment has replaced; answering "changed" on a cadence
        // tweak re-applies the whole fleet for nothing.
        let mut opts = options();
        assert!(
            !opts.apply_runtime(&runtime()),
            "the runtime the options already hold converges nothing"
        );

        let mut rotated = runtime();
        rotated.secrets = vec![updated_contracts::assignment::SecretReference {
            environment: "API_TOKEN".into(),
            secret: "service".into(),
            key: "token".into(),
        }];
        assert!(opts.apply_runtime(&rotated), "a new secret reference");

        let mut reinput = rotated.clone();
        reinput.inputs = std::collections::BTreeMap::from([(
            "endpoint".to_string(),
            updated_contracts::telemetry::OutputValue::String {
                value: "https://service.internal:8200".into(),
            },
        )]);
        assert!(opts.apply_runtime(&reinput), "a re-resolved input");

        let mut cadence = reinput.clone();
        cadence.timeouts.check_interval_seconds = 60;
        assert!(
            !opts.apply_runtime(&cadence),
            "a cadence change is picked up without touching the release"
        );
        assert_eq!(opts.timeouts.check_interval, Duration::from_secs(60));
    }

    #[test]
    fn every_converge_the_loop_runs_is_apply_reason_restart() {
        // A rotation, a re-resolved input, and a repaired bundle all reach the release the same
        // way: `apply --reason restart`, which is the reconciler's cue to re-converge whatever it
        // owns onto the current values. `install` is the first boot's alone.
        let source = include_str!("main.rs");
        let loop_body = &source[source
            .find("let flow: Result<TickFlow")
            .expect("the cycle body is one expression")..];
        // Spelled in halves so this assertion does not count itself.
        let call = concat!("converge_", "environment(&opts, &store,");
        let restart = concat!(
            "converge_",
            "environment(&opts, &store, LifecycleReason::Restart)"
        );
        let converges = loop_body.matches(call).count();
        assert_eq!(converges, 2, "the repair arm and the runtime arm");
        assert_eq!(
            loop_body.matches(restart).count(),
            converges,
            "every in-loop converge is a restart-reason apply"
        );
    }

    #[test]
    fn a_bad_disk_is_still_recognised_behind_a_post_commit_wrapper() {
        // `foundation::durable` wraps a failure that happens AFTER the rename landed, so the
        // guardian does not roll back a pointer that already moved. Attaching that marker costs the
        // `io::Error` its raw-code representation (`Os` and `Custom` are alternatives), so the errno
        // is only reachable one `source` hop down — the shape rebuilt here, and the contract
        // foundation documents on `Unsynced` and pins with its own regression test. A bad disk is a
        // fault of the node either way and must still be waited out from behind readiness.
        #[derive(Debug)]
        struct PostCommit(io::Error);
        impl std::fmt::Display for PostCommit {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
        impl std::error::Error for PostCommit {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let bad_disk = io::Error::from_raw_os_error(libc::EIO);
        let wrapped = io::Error::new(bad_disk.kind(), PostCommit(bad_disk));
        assert_eq!(
            wrapped.raw_os_error(),
            None,
            "the wrapper is what makes the top-level code unreadable — the premise of this test"
        );
        assert!(
            is_node_local_transient(&wrapped),
            "a post-commit fsync EIO is a bad disk, not a bad release"
        );
    }

    #[test]
    fn only_a_node_local_transient_inside_the_budget_is_retried() {
        let shutdown = AtomicBool::new(false);
        let now = Instant::now();
        let deadline = now + TransientRetry::BOOT.budget;

        // The exact states a candidate supervisor's boot recovery hits on a full state volume, a
        // read-only remount, a bad disk, and a CDN blip. None of them says anything about these
        // supervisor bytes, so none of them may end in a rejection by content hash.
        for error in [
            io::Error::from(io::ErrorKind::StorageFull),
            io::Error::from(io::ErrorKind::ReadOnlyFilesystem),
            io::Error::from_raw_os_error(libc::EIO),
            io::Error::from(io::ErrorKind::NetworkUnreachable),
            io::Error::from(io::ErrorKind::ConnectionReset),
        ] {
            assert!(
                retry_after_transient(&error, now, deadline, &shutdown),
                "{error:?} is a fault of the node, so it is waited out from behind readiness"
            );
        }

        // A fault the state or the release owns is not retried at all: it is exactly as true on
        // the next attempt, and a supervisor that never exits is the worse failure.
        for error in [
            io::Error::from(io::ErrorKind::InvalidData),
            io::Error::from(io::ErrorKind::NotFound),
            io::Error::from(io::ErrorKind::PermissionDenied),
        ] {
            assert!(!retry_after_transient(&error, now, deadline, &shutdown));
        }

        let transient = io::Error::from(io::ErrorKind::StorageFull);
        assert!(
            !retry_after_transient(&transient, deadline, deadline, &shutdown),
            "the retry is bounded; a spent budget exits like any unrecoverable step"
        );
        shutdown.store(true, Ordering::SeqCst);
        assert!(
            !retry_after_transient(&transient, now, deadline, &shutdown),
            "a requested stop outranks the retry"
        );
    }

    #[test]
    fn the_boot_retry_budget_outlasts_the_guardians_readiness_and_confirmation_windows() {
        // The shipped guardian defaults (bootstrap/src/main.rs): 45s to prove ready, then a 30s
        // confirmation window. The budget must outlast their sum, because that is what makes the
        // retry safe: a candidate that spends the transient behind its readiness signal is
        // COMMITTED, so an exit after the budget is an ordinary relaunch, not a permanent,
        // by-content-hash rejection.
        let guardian_windows = Duration::from_secs(45) + Duration::from_secs(30);
        assert!(
            TransientRetry::BOOT.budget > guardian_windows,
            "a boot-recovery retry budget of {:?} does not outlast the guardian's {guardian_windows:?}",
            TransientRetry::BOOT.budget
        );
        assert!(TransientRetry::BOOT.interval < TransientRetry::BOOT.budget);
    }

    #[test]
    fn the_identity_tick_cannot_stall_the_loop_into_a_health_drain() {
        // The tick runs inline on the loop that emits the heartbeat, so its bound is a health
        // property: a stall anywhere near REPORT_FRESHNESS drains a healthy node out of rotation.
        // Its own network legs are bounded only individually (60s + 30s + 60s), which is why one
        // deadline over the whole tick exists at all.
        assert!(
            IDENTITY_TICK_DEADLINE * 2 < updated_contracts::telemetry::REPORT_FRESHNESS,
            "an identity tick of {IDENTITY_TICK_DEADLINE:?} is not well inside the {:?} freshness \
             window the healthproxy drains on",
            updated_contracts::telemetry::REPORT_FRESHNESS
        );
    }

    #[test]
    fn a_marker_is_forwarded_for_rejection_exactly_when_the_rejection_record_would_take_it() {
        // Regression: `execute_boot_plan` decides up front whether a rejected-supervisor marker
        // names a candidate worth recording, and `SelfUpdateState::reject_candidate` then hands
        // that hash to `Rejections::reject`. If the two grammars ever disagree, a marker this
        // forwards fails the boot with `InvalidData` — and the marker is only ever cleared after a
        // successful write, so every subsequent boot fails identically: the permanent boot loop.
        // They cannot disagree by construction now (both go through
        // `updated::reject::is_rejection_key`); this pins that they agree in behaviour too.
        let digest: String = std::iter::repeat_n('a', 64).collect();
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("marker-agreement");
        for candidate in [
            digest.clone(),
            format!("{digest}:{digest}"),
            digest.to_ascii_uppercase(),
            "not-a-digest".into(),
            String::new(),
            format!("{digest}:"),
            format!("{digest}:{digest}:{digest}"),
        ] {
            let marker = std::path::Path::new("/var/lib/updated/supervisors")
                .join(&candidate)
                .join("supervisor");
            let forwarded = rejected_supervisor_hash(&marker).is_some();
            let mut rejections = updated::reject::Rejections::load(&path).unwrap();
            let recordable = rejections.reject(&candidate).is_ok();
            std::fs::remove_file(&path).ok();
            assert_eq!(
                forwarded, recordable,
                "{candidate:?}: forwarded={forwarded} but the rejection record would take it \
                 ={recordable}"
            );
        }
    }
}
