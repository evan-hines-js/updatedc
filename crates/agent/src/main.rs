#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! The node agent: a package runner. It pulls signed TUF bundles, activates them through a
//! durable transaction, and invokes the release's own reconciler hooks — `converge`, `healthcheck`,
//! `rollback`, `inspect`. It never launches, signals, or holds a PID of any workload. The agent
//! is restarted and upgraded by the platform service manager.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use updated::config::{Application, Paths, Routing, Timeouts};
/// The reconciler protocol vocabulary is defined once, in the contracts crate, and shared with
/// every reconciler implementation in this workspace.
use updated_contracts::reconciler::{
    attempt, HostAction, MutationOperation, ObservationOperation, Operation, Reason,
};
use updated_contracts::telemetry::REPORT_CADENCE_JITTER_PERCENT;
mod acquire;
mod boot;
mod domain;
mod fingerprint;
mod gc;
mod heartbeat;
mod host;
mod install;
mod options;
mod recovery;
mod repair;
mod runtime_data;
mod schedule;
mod selection;
mod store;
mod telemetry;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test_support;
mod transient;
mod update;

use boot::{plan_boot, GateFailure};
use domain::*;
use gc::*;
use heartbeat::*;
use install::ensure_installed;
use options::*;
use recovery::*;
use repair::*;
use schedule::*;
use selection::*;
use store::*;
use transient::*;
use update::*;

use updated_tuf::TrustedRepository;

const SELF_VERSION: &str = env!("CARGO_PKG_VERSION");

struct Options {
    helper_executable: PathBuf,
    deployment: String,
    assignment_sha256: String,
    routing: Routing,
    application: Application,
    /// Sensitive input bytes resolved from `application.input_selection`; never persisted in the
    /// signed boot config or copied into telemetry.
    inputs: updated_contracts::dataflow::FileSnapshot,
    timeouts: BoundedTimeouts,
    storage: updated_contracts::assignment::ManagedStorage,
    /// Canonical bundle installation layout.
    paths: Paths,
    runtime_data: runtime_data::RuntimeDataManager,
    /// Latched until the currently resolved inputs survive a successful reconciler converge.
    runtime_converge_pending: bool,
    identity_renewal: IdentityRenewal,
}

struct IdentityRenewal {
    config: PathBuf,
    state_dir: PathBuf,
}

impl Options {
    /// Reconcile the managed runtime against the live assignment resolved this cycle. The
    /// runtime (product/channel identity, repository limits, cadence, retention, and inputs) is
    /// signed into the SAME assignment that carries the version and provider set, so a
    /// control-plane reassignment can change it with no version bump. The version/provider are
    /// reconciled by `check_application`; this reconciles everything else onto the one live source.
    ///
    /// Returns whether the machine is stale on the new runtime — changed resolved inputs reach the
    /// release only through a reconciler invocation, so the caller answers this by running the
    /// environment converge
    /// (`converge_environment`), which is the one thing that can act on them.
    fn apply_runtime(
        &mut self,
        runtime: &updated_contracts::assignment::ManagedRuntime,
        inputs: updated_contracts::dataflow::FileSnapshot,
    ) -> bool {
        self.runtime_converge_pending |=
            self.application.input_selection != runtime.inputs || self.inputs != inputs;
        // `install_root` needs no reconciliation: `TrustedRepository::assigned` fails closed on
        // any assignment whose root is not exactly the one this process resolved its paths from
        // (`usable_as_boot_config`), so an assignment that reaches here can only carry the boot
        // root. Moving a node's install root is a migration, done by restarting on a new config.
        self.application = Application::from_runtime(runtime);
        self.inputs = inputs;
        self.timeouts = BoundedTimeouts::new(Timeouts::from_runtime(runtime));
        self.storage = runtime.storage.clone();
        self.runtime_converge_pending
    }

    fn runtime_converged(&mut self) {
        self.runtime_converge_pending = false;
    }

    /// Whether the release has successfully observed the input selection in this assignment.
    /// Heartbeats ask this directly, so a failure before [`Self::apply_runtime`] (notably an S3
    /// fetch failure) cannot report the new assignment healthy on the old files.
    fn runtime_is_converged(
        &self,
        runtime: &updated_contracts::assignment::ManagedRuntime,
    ) -> bool {
        !self.runtime_converge_pending && self.application.input_selection == runtime.inputs
    }
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
/// Boot, update transactions, and routine convergence all use [`update::became_healthy`].
/// [`HealthWatch::reconverging`] invalidates readiness before mutation; routine convergence
/// replaces that provisional value with its bounded gate's verdict before the cycle reports.
struct HealthWatch {
    next_probe: Instant,
    /// Latest readiness observation, so a report reflects whether the deployed release is
    /// actually serving. False until an observation says otherwise — an unsampled release and one
    /// sampled unready are both reported unsettled, so they are the same state here.
    last_ready: bool,
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
            last_ready: ready,
        }
    }

    /// Re-arm immediately before the loop converges a runtime reassignment, repaired bytes, or a
    /// release update. Nothing has proven the about-to-be-applied state healthy, so reporting turns
    /// unready before any partial side effect can occur and the next probe receives the configured
    /// `health_grace`.
    ///
    /// Without the grace, a release that is merely still starting is reported unready — fleet-wide
    /// and simultaneously, on a benign reassignment — and the healthproxy drains every node that
    /// obeyed the assignment.
    fn reconverging(&mut self, timeouts: &Timeouts) {
        self.next_probe = Instant::now() + timeouts.health_grace;
        self.last_ready = false;
    }

    /// Record one periodic observation and schedule the next probe.
    fn observed(&mut self, now: Instant, healthy: bool, timeouts: &Timeouts) {
        self.next_probe = now + timeouts.health_interval;
        self.last_ready = healthy;
    }
}

/// The loop's one non-transactional reconvergence path. Readiness turns false before `converge` can make a
/// partial side effect; a caller therefore cannot publish old readiness or outputs under the
/// changed assignment when convergence fails.
async fn reconverge_environment(
    opts: &Options,
    store: &Store,
    health: &mut HealthWatch,
) -> io::Result<updated_contracts::reconciler::SuccessfulMutation> {
    health.reconverging(&opts.timeouts);
    let result = converge_environment(
        opts,
        store,
        Reason::Restart,
        attempt::CONVERGE,
        Some(update::STEADY_STATE_CONVERGE_TIMEOUT),
    )?;
    if result.host_action() != HostAction::Reboot {
        let Installed::Present(installed) = store.installed()? else {
            return Err(io::Error::other("no installed release after convergence"));
        };
        let target = ReleaseTarget {
            release: &installed.release,
            archive_sha256: &installed.archive_sha256,
        };
        let mut reconciler = ReleaseReconciler::new(opts, &installed.reconciler, Reason::Restart);
        let verdict =
            update::became_healthy(&mut reconciler, attempt::CONVERGE, target, target).await;
        health.observed(
            Instant::now(),
            matches!(verdict, update::Health::Ready),
            &opts.timeouts,
        );
    }
    Ok(result)
}

fn main() {
    if let Some(code) = updated::native_runtime::dispatch()
        .or_else(updated::command_adapter::control_dispatch)
        .or_else(updated::command_adapter::dispatch)
    {
        std::process::exit(if code == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        });
    }
    if let Some(code) = updated::helper::dispatch() {
        std::process::exit(if code == std::process::ExitCode::SUCCESS {
            0
        } else {
            1
        });
    }
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
    let (opts, _enrollment_lock) = match runtime.block_on(parse_args()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("agent: {e}\n");
            usage();
            std::process::exit(2);
        }
    };
    let reporter = telemetry::AttentionReporter::new(&opts);
    let result = runtime.block_on(run(opts));
    runtime.block_on(reporter.report());
    if let Err(e) = result {
        eprintln!("agent: fatal: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!("usage: updated-agent --config <config.toml>");
    eprintln!(
        "the config file contains the node name, enrollment URL, CA, and shared fleet cert paths"
    );
}

async fn run(mut opts: Options) -> Result<(), Box<dyn std::error::Error>> {
    // One owner protects the shared binary, state, journal, and staging paths.
    let _lock = opts
        .paths
        .lock_installation()
        .map_err(|e| format!("another agent already owns this install: {e}"))?;

    if let Some(hold) = updated::command_adapter::read_attention(&opts.paths.install_root)? {
        return Err(format!("operator attention required: {}", hold.message).into());
    }

    // Reconciler exchanges contain plaintext assigned inputs. `InvocationData::drop` removes the
    // ordinary case; this is the crash-recovery half of the same ownership rule. Run it only after
    // taking the instance lock, so no live invocation can be mistaken for a stale one.
    update::clear_stale_invocation_data(&opts.paths)?;

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

    // A completed hook may have requested reboot just before this process died. Honor it before
    // recovery, input fetching, any further hook, or a health verdict in the same OS boot.
    if host::reboot_pending(&opts.paths.pending_reboot)? {
        request_host_reboot(&shutdown).await?;
        return Ok(());
    }
    let mut store = Store::open(opts.paths.clone())?;

    // Reconcile any in-flight install journal and cold-install a fresh node, returning whether
    // this boot performed the install. That selects the boot converge's reason (install vs.
    // restart) so an operator script can seed on first boot and merely clean up on later
    // restarts. All first-install placement happens inside this durable, crash-recoverable
    // install; there is no first-install branch after it.
    let first_install = ensure_installed(&opts, &mut store).await?;

    // Whether this boot repaired a damaged committed tree. A permanent, hash-keyed rejection may
    // never be charged to bytes this boot re-downloaded and re-verified, so it is the one input
    // the boot gate's rejection decision needs that no durable record holds.
    let mut bytes_repaired = false;

    // The disk is not trusted merely because it was verified during installation. This
    // check is local and deliberately precedes every repository access. A modified
    // committed bundle is never converged onto, even when the network is unavailable.
    if let updated::state::Installed::Present(installed) = store.installed()? {
        if let Err(error) =
            updated::bundle::verify_release(&opts.paths.versions, &installed.release)
        {
            // The repaired-from repository is of no use on the boot path — there is no loop tick to
            // report for yet, and the ordinary heartbeat starts one refresh later.
            let repair = repair_committed_bundle(&opts, &mut store)
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
            //
            // The predecessor fallback repaired no bytes: it journaled a revert, which carries its
            // own (non-)rejection decision, and `gather_situation` below re-reads the store, so
            // that journal drives the rollback in this same boot with no further code here.
            if matches!(repair, Repair::FromAssignment(_)) {
                bytes_repaired = true;
            }
        }
    }

    // Gather the whole world into a Situation and let the pure boot planner decide
    // recovery, drift enforcement, and journaled rejections.
    let situation = gather_situation(&store)?;
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
    let current = plan.current.clone();

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
                .expect("pending reconciler recovery has a transaction"),
        )?;
    }
    if let Some(tx) = recovery_transaction.as_mut() {
        // Move a forward transaction onto the rollback path so its resume gates open. Every
        // recovery that reaches here can make this transition: `boot::journal_recovery` refuses to
        // hand back a journal whose phase cannot drive a rollback (a terminal `Committed` or
        // `RolledBack` file left behind by a tolerated `clear_journal` failure), and the
        // `pending`-derived rollbacks are synthesized already on the path.
        if !tx.is_rollback() {
            advance_transaction(&mut store, tx, TransactionPhase::RollbackPlanned)?;
        }
    }

    // Recovery uses the inputs pinned before this transaction touched the host. A newer live
    // assignment must not replace those credentials, and a network fault must not block rollback.
    let input_attempt = recovery_transaction
        .as_ref()
        .map(|tx| tx.id.as_str())
        .or_else(|| match &situation.installed {
            Installed::Present(state) => state
                .rollback_guard
                .as_ref()
                .map(|guard| guard.attempt_id.as_str()),
            _ => None,
        });
    let pinned = match input_attempt {
        Some(attempt) => opts
            .runtime_data
            .restore_pin(&opts.paths.recovery_inputs, attempt)?,
        None => false,
    };
    if pinned {
        opts.application.input_selection = opts.runtime_data.selection().clone();
    }
    if !pinned
        && !opts
            .runtime_data
            .acquire(
                &opts.assignment_sha256,
                &opts.application.input_selection,
                &shutdown,
            )
            .await
            .map_err(|error| {
                format!("boot input acquisition requires a fresh assignment: {error}")
            })?
    {
        log("shutdown requested while waiting for assigned runtime data; exiting");
        return Ok(());
    }
    opts.inputs = opts.runtime_data.inputs().clone();

    // Candidate compensation is its own completed-effect barrier. It runs with the candidate's
    // reconciler and payload before the predecessor pointer or machine state is touched.
    let recovery_action =
        recover_through_transients("candidate rollback recovery", &shutdown, || {
            complete_candidate_compensation(&opts, &mut store, recovery_transaction.as_mut())
        })
        .await?;
    if recovery_action == HostAction::Reboot {
        request_host_reboot(&shutdown).await?;
        return Ok(());
    }

    // Perform the plan's durable reconciliation (binary, rejections, commit), yielding the
    // still-unconfirmed update (if any) for the loop to confirm once its window passes.
    // A failure here leaves the journal intact and EXITS (see `exit_for_relaunch`), so the platform
    // service manager relaunches this agent and boot recovery re-derives
    // the identical, idempotent reconciliation from that durable evidence — unless the cause is a
    // node-local transient, which `recover_through_transients` waits out instead (see there).
    let mut pending = recover_through_transients("boot/update recovery", &shutdown, || {
        execute_boot_plan(
            &plan,
            &mut store,
            defer_recovery_commit,
            recovery_transaction.as_mut(),
        )
    })
    .await?;
    // Restore the predecessor's machine state (rollback recovery): the predecessor's own `converge`,
    // replayed under the transaction's identity — `complete_recovery_activation` resolves whether
    // this boot still owes it.
    let recovery_action =
        recover_through_transients("predecessor activation recovery", &shutdown, || {
            complete_recovery_activation(&opts, &mut store, recovery_transaction.as_mut())
        })
        .await?;
    if recovery_action == HostAction::Reboot {
        request_host_reboot(&shutdown).await?;
        return Ok(());
    }
    if pending.is_some() {
        if let Some(v) = current.as_deref() {
            log(&format!(
                "update {v} is unconfirmed; failed boot verification reverts it"
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

    // One reason for this whole boot, so the converge below and the gate after it can never
    // disagree about what kind of boot the reconciler is being asked to serve.
    let boot_reason = if first_install {
        Reason::Install
    } else {
        Reason::Restart
    };
    let installed_state = recover_through_transients(
        "reading installed state for the boot health gate",
        &shutdown,
        || match store.installed()? {
            Installed::Present(installed) => Ok(installed),
            Installed::Missing => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "cannot verify a boot without an installed release",
            )),
            Installed::Invalid => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot verify a boot with a corrupt installed release",
            )),
        },
    )
    .await?;
    let target = boot_gate_target(recovery_transaction.as_ref(), &installed_state, boot_reason);
    let mut reconciler = ReleaseReconciler::new(&opts, target.reconciler.as_ref(), target.reason);
    let mut convergence_failure = None;
    // The boot converge is the COMMITTED release's `converge` and never runs during recovery: a boot
    // resuming an interrupted update or rollback replays only that transaction's own minimal,
    // idempotent steps, and applying the committed candidate here while a rollback commit is still
    // deferred would converge the machine onto the very release the rollback is undoing. A rollback
    // recovery instead re-runs the predecessor's own `converge` on every boot until the rollback
    // completes — see [`complete_recovery_activation`].
    if recovery_transaction.is_none() {
        log(&format!(
            "starting reconciler converge for release {} with reason {}",
            current.as_deref().unwrap_or("<unknown>"),
            boot_reason.as_str()
        ));
        let convergence = recover_through_transients("boot reconciler converge", &shutdown, || {
            // Only infrastructure faults use the transient retry/exit path. A hook's own
            // failure must reach the same rejection/revert decision as a failed health gate.
            match reconciler.mutate(
                MutationOperation::Converge,
                &target.attempt,
                ReleaseTarget {
                    release: &target.candidate,
                    archive_sha256: &target.candidate_archive_sha256,
                },
                ReleaseTarget {
                    release: &target.predecessor,
                    archive_sha256: &target.predecessor_archive_sha256,
                },
            ) {
                Ok(result) => Ok(Ok(result)),
                Err(InvocationFailure::ReleaseFault(error)) => Ok(Err(error)),
                Err(InvocationFailure::Inconclusive(error)) => Err(error),
            }
        })
        .await?;
        match convergence {
            Ok(result) => {
                if result.host_action() == HostAction::Reboot {
                    request_host_reboot(&shutdown).await?;
                    return Ok(());
                }
                log(&format!(
                    "reconciler converge for release {} completed; entering the boot health gate",
                    current.as_deref().unwrap_or("<unknown>")
                ));
            }
            Err(error) => {
                warn(&format!("boot reconciler converge failed ({error})"));
                convergence_failure = Some(error);
            }
        }
    }
    // Gate readiness: the release's own `healthcheck` must pass before this boot is trusted. It is
    // the only health source — the agent owns no workload process to observe — and readiness was
    // evaluated only after convergence has completed.
    //
    // During a crash-recovered rollback the predecessor commit is deferred until *after* this gate,
    // so `store.installed()` still holds the CANDIDATE record. Gate the restored predecessor with
    // ITS OWN reconciler — carried in the recovery transaction from the rollback guard (the operator
    // set staged for exactly this rollback) — not the candidate's. Otherwise an update that revised
    // the reconciler, then failed, would gate the healthy predecessor with the candidate's
    // hooks, reject it, and crash-loop a good release.
    // Attempt identity, release identity and providers are resolved together, from one source, so
    // the gate can never observe one release with another's hooks or under another's attempt.
    let gate = if let Some(error) = convergence_failure {
        update::Health::Unhealthy(error)
    } else {
        log(&format!(
            "starting boot health gate for release {} with reason {}",
            target.candidate.version,
            target.reason.as_str()
        ));
        update::became_healthy(
            &mut reconciler,
            &target.attempt,
            ReleaseTarget {
                release: &target.candidate,
                archive_sha256: &target.candidate_archive_sha256,
            },
            ReleaseTarget {
                release: &target.predecessor,
                archive_sha256: &target.predecessor_archive_sha256,
            },
        )
        .await
    };
    match &gate {
        update::Health::Ready => log(&format!(
            "boot health gate passed for release {}",
            target.candidate.version
        )),
        update::Health::Unhealthy(cause) => warn(&format!(
            "boot health gate reported release {} unhealthy ({cause})",
            target.candidate.version,
        )),
        update::Health::Inconclusive(cause) => {
            // No verdict about these bytes: the probes stopped reaching the node reconciler (a
            // corrupt or pruned provider tree, ENOSPC/EACCES/EIO preparing the invocation), so
            // this says more about the disk than about the release. Note it — and then fall
            // through to the SAME bounded failure path an unhealthy gate takes: these faults are
            // deterministic (a provider tree that will not resolve resolves no better on the next
            // boot), so treating them as "try again later" would relaunch into the identical
            // failure forever.
            warn(&format!(
                "the boot readiness gate for release {} could not reach the node reconciler \
                 ({cause}); treating it as a failed gate so the bounded recovery below still \
                 terminates",
                target.candidate.version
            ));
        }
    }
    let gate_passed = matches!(gate, update::Health::Ready);
    if !gate_passed {
        let mut gate_failure_state: &updated::state::InstalledState = installed_state.as_ref();
        // A crash-recovered rollback whose restored predecessor cannot pass the gate is the
        // dangerous case: the still-deferred `store.installed()` holds the CONFIRMED candidate, not
        // the predecessor, so without a bound the service manager restarts the agent, the journal re-derives the
        // identical rollback, and it runs forever with nothing converged. Bound it: count failures
        // durably in the journal (which is what survives the relaunch) and, once the limit is hit,
        // finish the rollback onto the exact previously confirmed predecessor and report its current
        // health as unhealthy. Repository history is not a recovery policy.
        if let Some(tx) = recovery_transaction.as_mut().filter(|tx| tx.is_rollback()) {
            let predecessor = tx.previous_release.version.clone();
            match bound_unhealthy_rollback(&mut store, tx) {
                Ok(RollbackHealthOutcome::SettledUnhealthy) => {
                    gate_failure_state = plan.commit.as_ref().ok_or(
                        "a bounded rollback settlement has no predecessor state to commit",
                    )?;
                    warn(&format!(
                        "rollback target {predecessor} is unhealthy after \
                         {MAX_ROLLBACK_HEALTH_ATTEMPTS} attempts; settling on that exact previously \
                         confirmed release and reporting it unhealthy"
                    ));
                }
                Ok(RollbackHealthOutcome::Retry(attempt)) => {
                    warn(&format!(
                        "rollback target {predecessor} unhealthy (attempt {attempt} of \
                         {MAX_ROLLBACK_HEALTH_ATTEMPTS}); retrying the same predecessor on the next boot"
                    ));
                    return Err("the rollback target failed its health gate".into());
                }
                Err(error) => {
                    return Err(exit_for_relaunch(
                        "rollback compensation before settling on the predecessor",
                        &error,
                    ));
                }
            }
        }
        // Classify every failed gate through the same policy. During a bounded rollback settlement
        // the installed file intentionally still names the failed candidate until the common
        // recovery commit below, so use the exact confirmed predecessor state that commit will
        // make authoritative. It classifies as report-only and cannot start a second rollback from
        // the already-terminal journal.
        match boot::plan_gate_failure(gate_failure_state) {
            GateFailure::Revert => {
                if let Err(error) =
                    revert_guarded_head(&mut store, &installed_state, bytes_repaired)
                {
                    return Err(exit_for_relaunch("recording the revert", &error));
                }
                return Err(
                    "the unconfirmed release failed its boot health gate; reverting on the next \
                     boot"
                        .into(),
                );
            }
            GateFailure::RejectProvisional => {
                if let Err(error) = reject_provisional_head(&mut store, &installed_state) {
                    return Err(exit_for_relaunch(
                        "rejecting the failed provisional head",
                        &error,
                    ));
                }
                return Err("the provisional head failed its boot health gate".into());
            }
            // A confirmed release that is unhealthy is REPORTED, never reverted locally: the
            // reconciler owns the workload and may converge it later, and there is no predecessor
            // image left to revert to. Exiting instead would hand the node to the init system's
            // restart loop with nothing to fix on the next boot.
            GateFailure::Report => warn(&format!(
                "the committed release {} is unhealthy; reporting it and continuing to \
                     reconcile",
                gate_failure_state.release.version
            )),
        }
    }
    // A head that proved healthy this boot can now be confirmed, so a later transient unhealth of
    // that proven head is reported and reconciled rather than rejected as a broken head. A bounded
    // unhealthy rollback settlement deliberately continues below without confirming anything.
    if gate_passed {
        // Confirmation is one store operation so both of its installed-state reads remain inside
        // the same Windows sharing/lock retry boundary.
        let newly_confirmed =
            recover_through_transients("confirming the health-proven release", &shutdown, || {
                store.prove_provisional()
            })
            .await?;
        if newly_confirmed {
            log(&format!(
                "release {} reached a confirmed installed state",
                target.candidate.version
            ));
        }
    }
    if recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.recovery_pending(TransactionPhase::RollbackVerified))
    {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_HEALTH_PASSED);
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::RollbackVerified)?;
    }

    let rollback_incomplete = recovery_transaction
        .as_ref()
        .is_some_and(|tx| tx.recovery_pending(TransactionPhase::RolledBack));
    if rollback_incomplete {
        let tx = recovery_transaction.as_mut().expect("checked above");
        advance_transaction(&mut store, tx, TransactionPhase::RolledBack)?;
    }
    if defer_recovery_commit {
        if let Some(state) = &plan.commit {
            store.commit_installed(state)?;
            pending = installed_rollback_guard(&store)?;
        }
    }
    // Keep the journal until both release reconciliation and any environmental rollback
    // have succeeded. If this agent dies, the next boot sees the same evidence and repeats the
    // idempotent recovery instead of declaring success.
    if plan.clear_journal || defer_recovery_commit {
        store.clear_journal()?;
    }
    garbage_collect(&opts, &store);

    run_steady_state(SteadyState {
        opts,
        shutdown,
        store,
        rollback_guard: pending,
        current,
        boot_gate_passed: gate_passed,
    })
    .await
}

struct SteadyState {
    opts: Options,
    shutdown: Arc<AtomicBool>,
    store: Store,
    rollback_guard: Option<updated::state::RollbackGuard>,
    current: Option<String>,
    boot_gate_passed: bool,
}

async fn run_steady_state(state: SteadyState) -> Result<(), Box<dyn std::error::Error>> {
    let SteadyState {
        mut opts,
        shutdown,
        mut store,
        rollback_guard: mut pending,
        mut current,
        boot_gate_passed,
    } = state;

    let mut loop_state = LoopState::new(opts.timeouts.check_interval);
    // The boot gate is this boot's first observation, whichever way it went: steady-state probing
    // starts one interval from here, and the node's first report carries what the gate saw rather
    // than claiming nothing is known. Pool membership follows from that report — the healthproxy is
    // the only path into rotation, and this agent never touches it directly.
    let mut health = HealthWatch::after_boot_gate(&opts.timeouts, boot_gate_passed);
    // Remote telemetry has exactly two clients: mTLS for capability acquisition and anonymous TLS
    // for spending that capability. A broken remote identity is a configuration error, never an
    // excuse to silently downgrade. Local file repositories have no telemetry endpoint, so they
    // use one inert anonymous client without requiring node credentials.
    let routing_is_local = opts
        .routing
        .is_local()
        .map_err(|error| format!("invalid routing base URL: {error}"))?;
    let (telemetry_control_client, telemetry_object_client) = if routing_is_local {
        let client = updated::tls::anonymous_object_client()?;
        (client.clone(), client)
    } else {
        (
            opts.routing.mtls.reqwest_control_client()?,
            opts.routing.mtls.reqwest_capability_client()?,
        )
    };
    let signing_key = load_report_signing_key(
        (!routing_is_local).then_some(opts.routing.mtls.client_key.as_path()),
    )?;
    let mut heartbeat = Heartbeat {
        control_client: telemetry_control_client,
        object_client: telemetry_object_client,
        control_base: (!routing_is_local).then_some(opts.routing.base_url.clone()),
        node: telemetry::node_identity(&opts.routing),
        // The node signs each report with the SAME per-node key that certifies its mTLS leaf, so
        // the control plane verifies authenticity end-to-end (not just on the write hop). Loaded
        // once as PKCS#8 DER. A remote node cannot run without it: silently omitting authenticated
        // reports would stall rollout settlement and every output dependency while the workload
        // kept changing. Only an explicitly local repository has no report channel or key.
        signing_key,
        refusal: telemetry::Refusal::default(),
        outputs: telemetry::OutputPublisher::default(),
    };
    let mut fingerprints = fingerprint::Tracker::new(Instant::now());
    // The last repository this node resolved. Kept across cycles so the heartbeat has something to
    // report off even on a cycle that could not reach the control plane: the report endpoint and
    // the metadata endpoint fail independently, and a node that cannot refresh is exactly the node
    // whose silence would be misread as death.
    let mut last_repo: Option<TrustedRepository> = None;
    loop {
        // Keep the guard until a fresh bounded gate proves the candidate healthy. Elapsed
        // time alone is not evidence: the workload can fail while this agent stays alive.
        let confirm_due = pending
            .as_ref()
            .is_some_and(|p| window_passed(p, opts.timeouts.confirmation_window, now_unix()));
        let mut confirmation_ready = false;
        if pending.is_some()
            && (Instant::now() >= health.next_probe || (confirm_due && health.last_ready))
        {
            let Installed::Present(installed) = store.installed()? else {
                return Err("an unconfirmed update has no installed release".into());
            };
            let target = ReleaseTarget {
                release: &installed.release,
                archive_sha256: &installed.archive_sha256,
            };
            let mut reconciler =
                ReleaseReconciler::new(&opts, &installed.reconciler, Reason::Restart);
            match update::became_healthy(&mut reconciler, attempt::PERIODIC, target, target).await {
                update::Health::Ready => confirmation_ready = true,
                update::Health::Unhealthy(error) => {
                    warn(&format!(
                        "unconfirmed release failed its health gate: {error}"
                    ));
                    revert_guarded_head(&mut store, &installed, false)?;
                    return Err(
                        "unconfirmed release became unhealthy; restarting for rollback".into(),
                    );
                }
                update::Health::Inconclusive(error) => {
                    warn(&format!("confirmation health gate was inconclusive; retaining rollback protection: {error}"));
                }
            }
            health.observed(Instant::now(), confirmation_ready, &opts.timeouts);
        }
        let mut confirm_failed = confirm_due && !confirmation_ready;
        if confirm_due && confirmation_ready {
            if disarm_update_rollback(&mut store) {
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
        let mut wait = app_wait;
        wait = wait.min(health.next_probe.saturating_duration_since(now));
        wait = wait.min(
            loop_state
                .next_identity_check
                .saturating_duration_since(now),
        );
        let wait = wait.max(Duration::from_millis(100));

        if sleep_interruptible(wait, &shutdown).await {
            log("shutdown requested; exiting (workloads keep running under the release's hooks)");
            return Ok(());
        }

        let now = Instant::now();
        if now >= loop_state.next_identity_check {
            const IDENTITY_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
            loop_state.next_identity_check = now + IDENTITY_CHECK_INTERVAL;
            match updated::enrollment::NodeConfig::load(&opts.identity_renewal.config) {
                Ok(config) => {
                    // This tick now owns exactly one control operation: certificate renewal.
                    // Metadata and root rotation ride the ordinary live TUF/S3 refresh path.
                    let renewal = match tokio::time::timeout(
                        IDENTITY_TICK_DEADLINE,
                        updated::enrollment::renew_node_certificate_if_due(
                            &config,
                            &opts.identity_renewal.state_dir,
                        ),
                    )
                    .await
                    {
                        Ok(renewal) => renewal,
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "node certificate renewal exceeded {}s on this control loop",
                                IDENTITY_TICK_DEADLINE.as_secs()
                            ),
                        )),
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
                    "loading the node config for material renewal failed; retrying in 12h: {error}"
                )),
            }
        }
        if now >= health.next_probe && pending.is_none() {
            // One periodic `healthcheck` per tick is the node's whole readiness answer, invoked
            // through the provider the committed record names *now* — see `probe_steady_target`,
            // which is why this tick's target exists only inside the call. It is reported, never
            // acted on: past the confirmation window the reconciler owns the workload, and the
            // control plane owns what to do about an unhealthy one.
            let healthy = probe_steady_target(&store, |installed, archive_sha256, reconciler| {
                let target = ReleaseTarget {
                    release: installed,
                    archive_sha256,
                };
                let healthy = run_reconciler_observation(
                    reconciler,
                    &opts,
                    ObservationOperation::Healthcheck,
                    ReconcilerInvocation {
                        reason: Reason::Restart,
                        id: attempt::PERIODIC,
                        candidate: target,
                        predecessor: target,
                    },
                )
                .is_ok();
                if let Some(error) = fingerprints.poll(
                    now,
                    healthy,
                    heartbeat.node.as_deref().unwrap_or("unidentified-node"),
                    || {
                        prepare_fingerprint_job(
                            reconciler,
                            &opts,
                            ReconcilerInvocation {
                                reason: Reason::Restart,
                                id: attempt::FINGERPRINT,
                                candidate: target,
                                predecessor: target,
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
        let cycle = cycle_due(pending.is_some(), now, loop_state.next_app_check);
        if !cycle.due {
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
            if let updated::state::Installed::Present(installed) = store.installed()? {
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
                    let repaired_from = match repaired_from {
                        Repair::FromAssignment(repo) => *repo,
                        // The revert is journaled but nothing has moved: the record still names the
                        // candidate, so `current`, the heartbeat and the converge below would all
                        // speak for a release this node is no longer going to run. Exit and let the
                        // platform service restart into boot recovery, which is the one rollback path.
                        Repair::RollbackJournaled => {
                            return Err(exit_for_relaunch(
                                "repair fallback to the local predecessor",
                                &"the revert is journaled for boot recovery",
                            ));
                        }
                    };
                    current = match store.installed()? {
                        updated::state::Installed::Present(state) => Some(state.release.version),
                        _ => None,
                    };
                    // Re-derive the in-memory confirmation intent from the record the repair just
                    // wrote, exactly like every other divergence site. The assignment repair CARRIES
                    // an in-flight update's `pending` forward, so blanking it here would leave a
                    // durable `pending` this process can never confirm (only `confirm_due` ->
                    // `confirm_update`, off this local, clears it) — and the first failed health gate
                    // days later would be read by the boot gate as an unconfirmed release inside its
                    // window: a revert to the predecessor plus a permanent rejection of a release
                    // that had long since proven itself.
                    pending = installed_rollback_guard(&store)?;
                    // The SAME converge the runtime arm below runs, for the same reason: the
                    // reconciler owns every workload process, so `converge` is the only step that puts
                    // the repaired bytes into service. Without it the tampered image would keep
                    // running and the next probe would report it ready. NOT best effort: a converge
                    // that fails would leave the old image serving, so it propagates and this agent
                    // exits, leaving boot recovery to converge the repaired release.
                    let result =
                        reconverge_environment(&opts, &store, &mut health).await.map_err(|error| {
                            format!("converging the environment onto the repaired bundle: {error}")
                        })?;
                    if result.host_action() == HostAction::Reboot {
                        return Ok(TickFlow::Reboot);
                    }
                    // Take the repaired bundle through a LATER tick rather than falling through to the
                    // update check on this one: the check is legitimately due against the repaired
                    // release, but reaching it here would drive a whole update transaction over a
                    // release the reconciler has only just been asked to converge onto.
                    //
                    // Retry on the normal cadence. Drift that survives a repair (a reconciler
                    // `converge` writing into the content-addressed release directory) must not collapse
                    // the loop to its 100 ms floor and repeatedly re-run a full TUF refresh.
                    let retry = jitter(opts.timeouts.check_interval, REPORT_CADENCE_JITTER_PERCENT);
                    loop_state.next_app_check = Instant::now() + retry;
                    // Hand the repository the repair resolved to the heartbeat below. That report is
                    // the node's only word about itself, and this arm is one of the paths that ends a
                    // cycle early — under drift that survives the repair (the arm's own stated case) a
                    // silent cycle would drain the node one `REPORT_FRESHNESS` later for a reason no
                    // reader can see. It reports not-settled, which is simply what `reconverging`
                    // just made true.
                    last_repo = Some(repaired_from);
                    return Ok(TickFlow::Next);
                }
            }

            // Resolve the agent document afresh, then load its release repository.
            // One verified result serves the application check this cycle, and a
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
            // rest of the runtime — repository bounds, cadence, retention, and resolved inputs —
            // is signed into the same assignment and can change on a control-plane reassignment
            // with no version bump. Applying it here keeps every converge on the current contract.
            if let Some(assignment_context) = repo.assignment_context().filter(|_| pending.is_none()) {
                let assignment = assignment_context.document();
                let assignment_sha256 = assignment_context.sha256();
                match opts
                    .runtime_data
                    .reconcile(assignment_sha256, &assignment.runtime.inputs)
                    .await
                {
                    Ok(()) => {}
                    Err(error) => {
                        warn(&format!(
                            "assigned runtime data could not be reconciled; keeping the running application and retrying: {error}"
                        ));
                        let retry = jitter(opts.timeouts.refresh_retry, REPORT_CADENCE_JITTER_PERCENT);
                        loop_state.next_app_check = Instant::now() + retry;
                        return Ok(TickFlow::Next);
                    }
                };
                opts.deployment = assignment.deployment.clone();
                opts.assignment_sha256 = assignment_sha256.to_owned();
                let inputs = opts.runtime_data.inputs().clone();
                if opts.apply_runtime(&assignment.runtime, inputs) {
                    // The runtime changed under the deployed release. Resolved `inputs` reach the
                    // reconciler only through its input directory, so `converge --reason restart` is
                    // the one thing that can act on the change — the agent has no process of its
                    // own to reconfigure.
                    log("assignment runtime changed; converging the environment onto it");
                    fingerprints.restart_after_deployment(Instant::now());
                    // The SAME converge the boot path runs, through the same function. Readiness
                    // comes back only through the ordinary observed-healthy path once `reconverging`
                    // re-arms probing, so a converge that fails leaves this node reporting unready.
                    let result =
                        reconverge_environment(&opts, &store, &mut health).await.map_err(|error| {
                            format!("converging the environment onto the new runtime: {error}")
                        })?;
                    opts.runtime_converged();
                    if result.host_action() == HostAction::Reboot {
                        return Ok(TickFlow::Reboot);
                    }
                    // The re-applied release has its own gate verdict now. Let the next tick
                    // drive version/provider reconciliation against the updated runtime.
                    loop_state.next_app_check = Instant::now();
                    return Ok(TickFlow::Next);
                }
            }

            if cycle.updates {
                match check_application(&opts, repo, &mut store, || {
                    fingerprints.restart_after_deployment(Instant::now());
                    health.reconverging(&opts.timeouts);
                })
                .await
                {
                    AppOutcome::Upgraded {
                        version,
                        host_action,
                    } => {
                        current = Some(version);
                        // The commit recorded the update as unconfirmed; pick it up so its
                        // window is watched and a crash is caught on the next boot.
                        pending = installed_rollback_guard(&store)?;
                        garbage_collect(&opts, &store);
                        if host_action == HostAction::Reboot {
                            return Ok(TickFlow::Reboot);
                        }
                        // The transaction converged the machine onto a new release. What this
                        // watch holds — the last observation, the probe deadline set earlier in
                        // this same tick — describes the release it replaced, so re-arm as at
                        // every other converge rather than judging a fresh release on its
                        // predecessor's record.
                    }
                    AppOutcome::Unchanged => {
                        // Configuration management is continuous, not an install-only side effect:
                        // every verified steady-state cycle asks the committed reconciler to
                        // enforce its desired state even when release selection has nothing new.
                        // Scripts own idempotence; the platform owns making convergence recur.
                        fingerprints.pause_for_mutation();
                        let result = reconverge_environment(&opts, &store, &mut health).await.map_err(
                            |error| {
                                format!("periodically converging the desired state: {error}")
                            },
                        )?;
                        if result.changed() {
                            fingerprints.restart_after_deployment(Instant::now());
                        }
                        if result.host_action() == HostAction::Reboot {
                            return Ok(TickFlow::Reboot);
                        }
                    }
                    AppOutcome::RestartForRecovery => {
                        // A post-activation failure left a durable rollback journal. Terminate this
                        // disposable agent cleanly; the platform service restarts it and boot recovery
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
                Settlement {
                    settled: pending.is_none() && health.last_ready,
                    updating: pending.is_some(),
                },
                fingerprints.current(),
            )
            .await;
        if let Some(hold) = updated::command_adapter::read_attention(&opts.paths.install_root)? {
            return Err(format!("operator attention required: {}", hold.message).into());
        }
        match flow? {
            TickFlow::Next => {}
            TickFlow::Exit => return Ok(()),
            TickFlow::Reboot => {
                request_host_reboot(&shutdown).await?;
                return Ok(());
            }
        }
    }
}

/// Request a reboot and remain alive until the operating system begins shutdown.
///
/// Remaining alive avoids a service-manager restart racing a planned host transition. If the OS
/// accepted the request but never starts shutdown, fail after a bound so service supervision can
/// retry the still-required, idempotent convergence instead of leaving the node wedged forever.
async fn request_host_reboot(shutdown: &AtomicBool) -> Result<(), Box<dyn std::error::Error>> {
    tokio::task::spawn_blocking(host::request_reboot).await??;
    log("host reboot requested; waiting for the operating system to stop the agent");
    let deadline = Instant::now() + Duration::from_secs(10 * 60);
    while Instant::now() < deadline {
        if shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "the operating system accepted a reboot request but did not begin shutdown within 10 minutes",
    )
    .into())
}

/// How one cycle of the control loop ended.
enum TickFlow {
    /// Go around again.
    Next,
    /// Leave this agent process; the platform service restarts it.
    Exit,
    /// The reconciler requested a host reboot. The cycle has already reported the node unsettled.
    Reboot,
}

// ============================ application updates ============================

/// What one wake of the control loop owes, decided before any work is done.
///
/// A pending confirmation suppresses the update *check*, never the cycle. The cycle ends in the
/// node's only report, and a node that goes silent for the whole confirmation window is drained out
/// of load-balancer rotation immediately after every successful update — read as stale rather than
/// as "acted, not yet settled", which is the distinction `settled` exists to publish.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Cycle {
    /// The cycle clock fired: refresh the repository, reconcile the assignment, and report.
    pub(crate) due: bool,
    /// This cycle may also start a new application update. False while an update is unconfirmed:
    /// one rollout step at a time.
    pub(crate) updates: bool,
}

pub(crate) fn cycle_due(rollback_guard: bool, now: Instant, next_check: Instant) -> Cycle {
    let due = now >= next_check;
    Cycle {
        due,
        updates: due && !rollback_guard,
    }
}

pub(crate) fn log(msg: &str) {
    foundation::log::info("agent", msg);
}

pub(crate) fn warn(msg: &str) {
    foundation::log::warn("agent", msg);
}

pub(crate) fn error(msg: &str) {
    foundation::log::error("agent", msg);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::store::MemoryBackend;
    use crate::test_support::{deployment_rejection, digest, provider, release};
    use updated::bundle::ReleaseId;
    use updated::state::{Installed, InstalledState, RepositoryLineage};
    use updated::transaction::Phase;

    /// One loop tick's steady-state probe, recording exactly what it was lent.
    fn tick(store: &Store) -> (ReleaseId, Box<updated::state::ReconcilerRelease>) {
        probe_steady_target(store, |installed, _, reconciler| {
            (installed.clone(), Box::new(reconciler.clone()))
        })
        .expect("an installed record")
    }

    #[test]
    fn remote_reporting_requires_one_valid_owner_only_signing_key() {
        assert!(load_report_signing_key(None).unwrap().is_none());

        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("agent.key");
        let pem = updated::csr::generate_key().unwrap();
        foundation::durable::atomic_write(&key, ".report-key-", pem.as_bytes()).unwrap();
        assert!(load_report_signing_key(Some(&key)).unwrap().is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(
                load_report_signing_key(Some(&key)).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        let malformed = directory.path().join("malformed.key");
        foundation::durable::atomic_write(&malformed, ".report-key-", b"not a private key")
            .unwrap();
        assert_eq!(
            load_report_signing_key(Some(&malformed))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn an_unrecoverable_boot_step_ends_the_process_instead_of_holding_the_node_down() {
        // Regression: every one of these used to route into an infinite `while !shutdown { sleep }`
        // hold. A single failed durable write — ENOSPC recording a rejection, a read-only remount —
        // then meant the agent never exited, so the "next boot" that was supposed to redo the
        // recovery never happened, with the node serving nothing. End the process so the platform
        // service can start the next boot under its configured restart policy.
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
        // Two ticks of the health-probe loop with a normal journaled update between them, driven
        // through the same call the loop makes. The update commits a release AND a provider set of
        // its own, and `garbage_collect` protects only what the installed record names — so a provider
        // resolved once at boot named a bundle the very next collection was free to prune, after
        // which every periodic probe failed to resolve its command and the third one called
        // `application_failed`, terminal, on a tower that was serving fine.
        //
        // The re-read is now structural rather than a convention this test could only watch: the
        // target is *lent* to the probe for the length of one call, so hoisting it back out of the
        // loop cannot compile without a deliberate clone.
        let lineage = crate::test_support::lineage();
        let mut damaged = provider();
        damaged.definition_sha256 = digest("damaged-execution");
        let damaged_release = release("1.0.0", "damaged");
        let damaged_state = InstalledState::proven(
            lineage.clone(),
            damaged_release.clone(),
            digest("archive-damaged"),
            damaged.clone(),
        );
        let mut store = Store::memory(MemoryBackend {
            installed: Some(damaged_state.clone()),
            active: Some(damaged_release.clone()),
            ..MemoryBackend::default()
        });
        let at_boot = tick(&store);
        assert_eq!(at_boot, (release("1.0.0", "damaged"), damaged));

        let repaired = release("1.0.1", "repaired");
        let mut tx = Transaction {
            id: digest("probe-update"),
            previous_release: damaged_state.release.clone(),
            previous_archive_sha256: damaged_state.archive_sha256.clone(),
            previous_repository_lineage: damaged_state.repository_lineage.clone(),
            candidate_release: repaired.clone(),
            candidate_archive_sha256: digest("archive-repaired"),
            candidate_rejection_sha256: deployment_rejection(&digest("archive-repaired")),
            candidate_repository_lineage: lineage.clone(),
            candidate_rejection_required: false,
            previous_reconciler: damaged_state.reconciler.clone(),
            candidate_reconciler: provider(),
            rollback_health_failures: 0,
            phase: Phase::Prepared,
        };
        store.write_journal(&tx).unwrap();
        tx.advance(Phase::Activated).unwrap();
        store.write_journal(&tx).unwrap();
        tx.advance(Phase::Converged).unwrap();
        store.write_journal(&tx).unwrap();
        tx.advance(Phase::Verified).unwrap();
        store.write_journal(&tx).unwrap();
        store.activate(&repaired).unwrap();
        store
            .commit_installed(&InstalledState {
                repository_lineage: lineage,
                release: repaired.clone(),
                archive_sha256: digest("archive-repaired"),
                reconciler: provider(),
                rollback_guard: Some(RollbackGuard {
                    attempt_id: tx.id.clone(),
                    candidate_rejection_sha256: tx.candidate_rejection_sha256,
                    previous_release: tx.previous_release,
                    previous_archive_sha256: tx.previous_archive_sha256,
                    previous_repository_lineage: tx.previous_repository_lineage,
                    reconciler: tx.previous_reconciler,
                    committed_at: 1,
                }),
                maturity: Maturity::Proven,
            })
            .unwrap();

        let after_repair = tick(&store);
        assert_eq!(
            after_repair,
            (repaired, provider()),
            "each tick probes the provider its own record names, not the one named at boot"
        );
        // The collector derives its protected set from that same record, so probe and collector
        // cannot name different provider releases.
        match store.installed().unwrap() {
            Installed::Present(state) => assert_eq!(state.reconciler, after_repair.1),
            _ => panic!("expected the repaired record"),
        }
    }

    /// The store refuses to destroy a journal whose transaction still owes the machine a commit
    /// or a settled rollback. This is the structural guarantee behind "an abandoned rollback can
    /// never skip its compensation": no call site — present or future — can discard mid-flight
    /// evidence, because the refusal lives on the destroy operation itself. Pre-activation
    /// journals displaced nothing; a landed forward commit has transferred its exact rollback
    /// authority to `installed.rollback_guard`; and a finished rollback has committed its exact
    /// predecessor. Those proofs — never a terminal phase by itself — make a journal disposable.
    #[test]
    fn a_journal_that_owes_compensation_cannot_be_discarded() {
        for phase in Phase::ALL {
            let discardable = matches!(
                phase,
                Phase::Prepared | Phase::Converged | Phase::Verified | Phase::Committed
            );
            let situation = interrupted_revert(Some(phase));
            let installed = match situation.installed {
                Installed::Present(state) => Some(*state),
                Installed::Missing | Installed::Invalid => None,
            };
            let mut store = Store::memory(MemoryBackend {
                journal: situation.journal,
                installed,
                active: situation.active,
                ..MemoryBackend::default()
            });
            let cleared = store.clear_journal();
            assert_eq!(
                cleared.is_ok(),
                discardable,
                "clear_journal at {phase:?} must {}",
                if discardable { "succeed" } else { "be refused" }
            );
            assert_eq!(
                store.journal().unwrap().is_none(),
                discardable,
                "the journal at {phase:?} must {}",
                if discardable { "be gone" } else { "survive" }
            );
        }
        // No journal at all is trivially clearable — recovery retries a failed post-commit delete.
        assert!(Store::default().clear_journal().is_ok());
    }

    /// The one non-terminal phase whose journal can still be spent: a crash between the durable
    /// commit and the journal's own terminal write leaves `Verified` on disk while active
    /// and installed state prove the commit landed. The store admits exactly that evidence — and
    /// still refuses the same phase when the machine does NOT corroborate it.
    #[test]
    fn a_commit_that_landed_makes_its_journal_discardable() {
        let situation = interrupted_revert(Some(Phase::Verified));
        let tx = situation.journal.unwrap();
        let candidate = tx.candidate_release.clone();
        let landed = match situation.installed {
            Installed::Present(state) => *state,
            Installed::Missing | Installed::Invalid => panic!("expected committed candidate"),
        };
        let mut store = Store::memory(MemoryBackend {
            journal: Some(tx.clone()),
            installed: Some(landed),
            active: Some(candidate),
            ..MemoryBackend::default()
        });
        store.clear_journal().unwrap();
        assert!(store.journal().unwrap().is_none());

        // Same phase, but the machine still shows the predecessor: the commit did NOT land, the
        // transaction still owes it, and the journal survives.
        let mut unlanded = Store::memory(MemoryBackend {
            active: Some(tx.previous_release.clone()),
            journal: Some(tx),
            ..MemoryBackend::default()
        });
        assert!(unlanded.clear_journal().is_err());
        assert!(unlanded.journal().unwrap().is_some());
    }

    /// The other door into evidence destruction: persisting transaction B over transaction A's
    /// unsettled journal buries A's compensation obligation just as surely as deleting it. The
    /// same id admits only exact state-machine successors; a different id needs A settled.
    #[test]
    fn an_unsettled_journal_cannot_be_buried_by_another_transaction() {
        let situation = interrupted_revert(Some(Phase::Restored));
        let unsettled = situation.journal.unwrap();
        let candidate = InstalledState::proven(
            unsettled.candidate_repository_lineage.clone(),
            unsettled.candidate_release.clone(),
            unsettled.candidate_archive_sha256.clone(),
            provider(),
        );
        let mut store = Store::memory(MemoryBackend {
            journal: Some(unsettled.clone()),
            installed: Some(candidate.clone()),
            active: Some(candidate.release),
            ..MemoryBackend::default()
        });

        // The same transaction advancing is the normal durable path.
        let mut same = unsettled.clone();
        same.rollback_health_failures += 1;
        assert!(store.write_journal(&same).is_ok());

        // A different transaction must not bury it...
        let mut other = unsettled.clone();
        other.id = digest("another-attempt");
        other.phase = Phase::Prepared;
        assert!(store.write_journal(&other).is_err());
        assert_eq!(store.journal().unwrap().unwrap().id, unsettled.id);

        // ...until the first is settled.
        let mut settled = same;
        store.write_journal(&settled).unwrap();
        settled.advance(Phase::RolledBack).unwrap();
        store.write_journal(&settled).unwrap();
        store.activate(&settled.previous_release).unwrap();
        store
            .commit_installed(&InstalledState::proven(
                settled.previous_repository_lineage.clone(),
                settled.previous_release.clone(),
                settled.previous_archive_sha256.clone(),
                settled.previous_reconciler.clone(),
            ))
            .unwrap();
        assert!(store.write_journal(&other).is_ok());
    }

    /// A node whose update committed (installed = candidate, pending = predecessor) and whose
    /// revert a previous boot began — the active pointer is already back on the predecessor — with
    /// `journal` still on disk in the given phase.
    fn interrupted_revert(phase: Option<Phase>) -> Situation {
        let lineage = crate::test_support::lineage();
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let installed = InstalledState {
            repository_lineage: lineage.clone(),
            release: candidate.clone(),
            archive_sha256: digest("archive-two"),
            reconciler: provider(),
            rollback_guard: Some(updated::state::RollbackGuard {
                attempt_id: digest("attempt"),
                candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
                previous_release: predecessor.clone(),
                previous_archive_sha256: digest("archive-one"),
                previous_repository_lineage: lineage.clone(),
                committed_at: 100,
                reconciler: provider(),
            }),
            maturity: Maturity::Proven,
        };
        Situation {
            installed: Installed::Present(Box::new(installed)),
            active: Some(predecessor.clone()),
            journal: phase.map(|phase| Transaction {
                id: digest("attempt"),
                previous_release: predecessor,
                previous_archive_sha256: digest("archive-one"),
                previous_repository_lineage: lineage.clone(),
                candidate_release: candidate,
                candidate_archive_sha256: digest("archive-two"),
                candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
                candidate_repository_lineage: lineage,
                candidate_rejection_required: false,
                previous_reconciler: provider(),
                candidate_reconciler: provider(),
                rollback_health_failures: 0,
                phase,
            }),
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
        let source = crate::test_support::normalized_source(include_str!("main.rs"));
        // The writer itself lives with `Heartbeat`; the cycle below is its only caller.
        let emitter = concat!("telemetry::report_", "running_state(");
        assert_eq!(
            crate::test_support::normalized_source(include_str!("heartbeat.rs"))
                .matches(emitter)
                .count(),
            1,
            "reports must have exactly one writer"
        );
        assert_eq!(
            source.matches(emitter).count(),
            0,
            "and the cycle reaches it only through `Heartbeat::emit`"
        );
        // Match Rust tokens, not checkout line endings. Git may materialize this file as CRLF on
        // Windows; whitespace is not part of the invariant.
        let emit_call = concat!(".", "emit(");
        assert_eq!(
            source.matches(emit_call).count(),
            1,
            "exactly one emit call"
        );
        let block = source
            .find("let flow: Result<TickFlow")
            .expect("the cycle body is one expression");
        let tail = &source[block..];
        let emit = tail.find(emit_call).expect("the cycle ends in a report");
        assert!(
            tail[..emit].trim_end().ends_with("heartbeat"),
            "the cycle's one emit belongs to its Heartbeat"
        );
        assert!(
            !tail[..emit].contains("\n            continue;")
                && !tail[..emit].contains("\n        continue;"),
            "nothing inside the cycle body may reach the top of the loop; early exits return TickFlow"
        );
    }

    /// The committed record of an unconfirmed update, as the boot health gate finds it.
    fn unconfirmed_head() -> InstalledState {
        let lineage = crate::test_support::lineage();
        InstalledState {
            repository_lineage: lineage.clone(),
            release: release("2.0.0", "two"),
            archive_sha256: digest("archive-two"),
            reconciler: provider(),
            rollback_guard: Some(updated::state::RollbackGuard {
                attempt_id: digest("attempt"),
                candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
                previous_release: release("1.0.0", "one"),
                previous_archive_sha256: digest("archive-one"),
                previous_repository_lineage: lineage,
                committed_at: 100,
                reconciler: provider(),
            }),
            maturity: Maturity::Proven,
        }
    }

    #[test]
    fn output_retention_uses_the_same_manifest_identity_as_its_writer_and_reader() {
        let head = unconfirmed_head();
        let predecessor_manifest = head
            .rollback_guard
            .as_ref()
            .unwrap()
            .previous_release
            .manifest_sha256
            .clone();
        assert_ne!(head.release.manifest_sha256, head.archive_sha256);
        assert_ne!(
            head.rollback_guard
                .as_ref()
                .unwrap()
                .previous_release
                .manifest_sha256,
            head.rollback_guard
                .as_ref()
                .unwrap()
                .previous_archive_sha256
        );
        assert_eq!(
            protected_output_snapshot_manifests(&head),
            vec![head.release.manifest_sha256.clone(), predecessor_manifest],
            "GC must protect the exact paths reconciler output writes and telemetry reads"
        );
    }

    fn store_holding(installed: &InstalledState) -> Store {
        Store::memory(MemoryBackend {
            installed: Some(installed.clone()),
            active: Some(installed.release.clone()),
            ..MemoryBackend::default()
        })
    }

    #[test]
    fn a_failed_gate_inside_the_window_records_a_drivable_revert_and_the_rejection() {
        // The one local revert left in the agent, at its decision point: the release's
        // `healthcheck` would not pass at boot while the update was still unconfirmed, so the
        // exact candidate deployment is rejected and a rollback journal is left for the next boot
        // — the single rollback implementation. Recording the intent rather than performing it
        // here is what keeps that true.
        let head = unconfirmed_head();
        let mut store = store_holding(&head);

        revert_guarded_head(&mut store, &head, false).unwrap();

        let journal = store.journal().unwrap().expect("a durable rollback intent");
        assert!(journal.is_rollback());
        assert_eq!(journal.previous_release, release("1.0.0", "one"));
        assert!(journal.candidate_rejection_required);
        assert!(journal.recovery_pending(Phase::Restored));
        assert!(journal.recovery_pending(Phase::RolledBack));
        let rejection = &head
            .rollback_guard
            .as_ref()
            .unwrap()
            .candidate_rejection_sha256;
        assert!(store.is_rejected(&head.repository_lineage, rejection));
        assert!(!store.is_rejected(&head.repository_lineage, &digest("archive-two")));
    }

    #[test]
    fn a_repaired_boot_still_owes_the_revert_but_not_the_rejection() {
        // A rejection is permanent, so it may never be charged to a deployment whose application
        // this same boot re-downloaded and re-verified — the gate failed on a tree that no longer
        // exists. The revert is owed either way: it is reversible, and the next boot finds an intact
        // tree and charges a repeat failure to the exact deployment.
        let head = unconfirmed_head();
        let mut store = store_holding(&head);

        revert_guarded_head(&mut store, &head, true).unwrap();

        let journal = store.journal().unwrap().expect("the revert is still owed");
        assert!(journal.is_rollback());
        assert!(!journal.candidate_rejection_required);
        let rejection = &head
            .rollback_guard
            .as_ref()
            .unwrap()
            .candidate_rejection_sha256;
        assert!(
            !store.is_rejected(&head.repository_lineage, rejection),
            "the repair re-verified the application; the deployment must not be blacklisted"
        );
    }

    #[test]
    fn a_confirmed_release_that_fails_its_gate_is_only_reported() {
        // The other half of the policy: a release that has proven itself once is never reverted
        // locally on a later unhealthy gate. The reconciler owns the workload and may converge it,
        // there is no predecessor image left, and reverting would fight the assignment — so it is
        // reported unhealthy and the agent keeps reconciling.
        let confirmed = InstalledState::proven(
            crate::test_support::lineage(),
            release("2.0.0", "two"),
            digest("archive-two"),
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
        assert!(!HealthWatch::after_boot_gate(&timeouts, false).last_ready);
        assert!(HealthWatch::after_boot_gate(&timeouts, true).last_ready);
    }

    #[test]
    fn a_spent_journal_still_derives_a_drivable_revert() {
        // Regression: `switch_over` tolerates a failed `clear_journal`, and an agent can die
        // between `commit_installed` and the journal's terminal write — either way a spent
        // Verified/Committed journal survives. A later boot then finds the pointer already
        // back on the predecessor (the revert a failed gate began). `classify_recovery` reads
        // `RestorePredecessor`, but the phase machine refuses to BEGIN a rollback from a terminal
        // `Committed`, so returning that journal verbatim produced a "recovery" with no rollback
        // rank: every resume gate closed, the plan's reconciliation was silently discarded, and
        // the candidate's machine-state changes were never compensated.
        for phase in [Phase::Verified, Phase::Committed] {
            let mut tx = recovery_transaction(&interrupted_revert(Some(phase)))
                .unwrap_or_else(|| panic!("a spent {phase:?} journal still owes the revert"));
            if !tx.is_rollback() {
                tx.advance(Phase::RollbackPlanned)
                    .expect("a non-terminal journal is moved onto the rollback path");
            }
            assert_eq!(tx.previous_release, release("1.0.0", "one"));
            assert!(tx.recovery_pending(Phase::Restored));
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
    fn a_persistently_unhealthy_rollback_target_settles_without_inventing_a_release() {
        let lineage = crate::test_support::lineage();
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let tx = Transaction {
            id: digest("attempt"),
            previous_release: predecessor.clone(),
            previous_archive_sha256: digest("archive-one"),
            previous_repository_lineage: lineage.clone(),
            candidate_release: candidate.clone(),
            candidate_archive_sha256: digest("archive-two"),
            candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
            candidate_repository_lineage: lineage.clone(),
            candidate_rejection_required: true,
            previous_reconciler: provider(),
            candidate_reconciler: provider(),
            rollback_health_failures: 0,
            // Reproduce a later resume boot: a prior process recorded a healthy predecessor, then
            // a machine reboot lost the workload before this boot's authoritative gate. The
            // durable failure tally must remain writable at this phase too.
            phase: Phase::RollbackVerified,
        };
        let mut store = Store::memory(MemoryBackend {
            installed: Some(InstalledState::proven(
                lineage.clone(),
                candidate.clone(),
                digest("archive-two"),
                provider(),
            )),
            active: Some(predecessor.clone()),
            journal: Some(tx),
            ..MemoryBackend::default()
        });
        // A real rollback journal that requires rejection is created only after the candidate's
        // verdict is durable. Keep the synthetic machine state complete so the final clear proves
        // both the original rejection and this test's later predecessor rejection.
        store
            .reject_deployment(&lineage, &digest("archive-two"))
            .unwrap();

        // Each iteration models one boot that re-derives the rollback from the durable journal and
        // fails the predecessor's health gate. The loop must terminate on the exact predecessor,
        // never spin and never reinterpret repository history as a recovery plan.
        let mut outcomes = Vec::new();
        for _ in 0..MAX_ROLLBACK_HEALTH_ATTEMPTS + 5 {
            let mut derived = store.journal().unwrap().expect("the rollback journal");
            assert!(derived.is_rollback());
            let outcome = bound_unhealthy_rollback(&mut store, &mut derived).unwrap();
            let done = outcome == RollbackHealthOutcome::SettledUnhealthy;
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
                RollbackHealthOutcome::SettledUnhealthy,
            ],
            "the rollback must be bounded at {MAX_ROLLBACK_HEALTH_ATTEMPTS} attempts, then settle"
        );
        // Candidate compensation completed at an earlier barrier; predecessor health settlement
        // never invokes another reconciler mutation.
        // The bounded helper leaves finalization to the one ordinary recovery path. It must not
        // reject or rewrite the predecessor, because that would turn a failed direct update into a
        // hidden search for an intermediate release on the next boot.
        let predecessor_rejection = deployment_rejection(&digest("archive-one"));
        assert!(!store.is_rejected(&lineage, &predecessor_rejection));
        assert!(!store.is_rejected(&lineage, &digest("archive-one")));
        let terminal = store
            .journal()
            .unwrap()
            .expect("finalization still owns the journal");
        assert_eq!(terminal.phase, Phase::RolledBack);
        match store.installed().unwrap() {
            Installed::Present(state) => {
                assert_eq!(state.release, candidate);
                assert!(
                    state.is_proven(),
                    "the helper never rewrites committed state"
                );
            }
            _ => panic!("expected the pre-finalization candidate record"),
        }
    }

    #[test]
    fn bounded_unhealthy_settlement_does_not_repeat_candidate_compensation() {
        let lineage = crate::test_support::lineage();
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = Store::memory(MemoryBackend {
            installed: Some(InstalledState::proven(
                lineage.clone(),
                candidate.clone(),
                digest("archive-two"),
                provider(),
            )),
            active: Some(predecessor.clone()),
            journal: Some(Transaction {
                id: digest("attempt"),
                previous_release: predecessor.clone(),
                previous_archive_sha256: digest("archive-one"),
                previous_repository_lineage: lineage.clone(),
                candidate_release: candidate,
                candidate_archive_sha256: digest("archive-two"),
                candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
                candidate_repository_lineage: lineage.clone(),
                candidate_rejection_required: true,
                previous_reconciler: provider(),
                candidate_reconciler: provider(),
                // Two boots have already failed the gate; this is the boot that reaches the bound.
                rollback_health_failures: MAX_ROLLBACK_HEALTH_ATTEMPTS - 1,
                phase: Phase::Restored,
            }),
            ..MemoryBackend::default()
        });
        store
            .reject_deployment(&lineage, &digest("archive-two"))
            .unwrap();

        let mut derived = store.journal().unwrap().expect("the rollback journal");
        let outcome = bound_unhealthy_rollback(&mut store, &mut derived).unwrap();
        assert_eq!(outcome, RollbackHealthOutcome::SettledUnhealthy);
        let predecessor_rejection = deployment_rejection(&digest("archive-one"));
        assert!(!store.is_rejected(&lineage, &predecessor_rejection));
        assert!(!store.is_rejected(&lineage, &digest("archive-one")));
        assert_eq!(
            store
                .journal()
                .unwrap()
                .expect("finalization owns the journal")
                .phase,
            Phase::RolledBack
        );
        match store.installed().unwrap() {
            Installed::Present(state) => {
                assert_eq!(state.release.version, "2.0.0");
                assert!(state.is_proven());
            }
            _ => panic!("expected the pre-finalization candidate record"),
        }
    }

    #[test]
    fn every_pre_terminal_rollback_phase_still_owes_the_predecessor_converge() {
        // The resume gate on the predecessor's `converge` is "is this rollback still incomplete", not
        // "has the converge ever run": a machine reboot (rather than an agent kill) at any later
        // rollback phase leaves the predecessor's workload stopped, and the boot gate would then
        // fail a perfectly healthy release three times and reject it. The converge is idempotent, so
        // replaying it on every resume boot is the correct semantics.
        let mut tx = rollback_of_guarded(
            &unconfirmed_head(),
            unconfirmed_head().rollback_guard.as_ref().unwrap(),
            false,
        );
        for phase in [
            Phase::RollbackPlanned,
            Phase::Restored,
            Phase::RollbackVerified,
        ] {
            tx.phase = phase;
            assert!(
                tx.recovery_pending(Phase::RolledBack),
                "{phase:?} still owes a converged predecessor"
            );
        }
        tx.phase = Phase::RolledBack;
        assert!(!tx.recovery_pending(Phase::RolledBack));

        // Which is why recording the phase stays guarded: the machine admits only the true forward
        // edges, so a second resume boot must replay the converge without re-advancing.
        tx.phase = Phase::Restored;
        assert!(
            tx.advance(Phase::Restored).is_err(),
            "re-advancing into a phase already reached is rejected, so the advance stays guarded"
        );
    }

    #[test]
    fn the_compensating_direction_carries_its_own_stable_attempt_id() {
        // A reconciler that marks completion under the attempt id would skip the predecessor's
        // `converge` if it reused the forward token — the forward switchover already ran `converge` under
        // it for a different payload. The compensating identity is derived, so it is
        // identical on every replay and on every boot, and dashless so the reference hook's
        // `{attempt-id}-{operation}` effect names still split on the first `-`.
        let head = unconfirmed_head();
        let tx = rollback_of_guarded(&head, head.rollback_guard.as_ref().unwrap(), false);
        assert_ne!(tx.rollback_attempt_id(), tx.id);
        assert_eq!(tx.rollback_attempt_id(), tx.clone().rollback_attempt_id());
        assert!(!tx.rollback_attempt_id().contains('-'));
        assert!(!attempt::is_reserved(&tx.rollback_attempt_id()));
    }

    #[test]
    fn the_repair_fallback_journals_a_revert_the_next_boot_can_drive() {
        // The predecessor fallback is not a second, hook-free rollback implementation: it records
        // the rollback the committed record already owes and hands it to boot recovery, so the
        // candidate's machine-state changes are compensated by a real `rollback` invocation.
        let head = unconfirmed_head();
        let pending = head
            .rollback_guard
            .clone()
            .expect("an unconfirmed head has pending");
        let mut store = store_holding(&head);

        journal_predecessor_fallback(&mut store, &head, &pending).unwrap();

        assert_eq!(
            store.journal().unwrap(),
            Some(rollback_of_guarded(&head, &pending, false)),
            "the fallback's revert is the one shape every other revert produces"
        );
        let rejection = &head
            .rollback_guard
            .as_ref()
            .unwrap()
            .candidate_rejection_sha256;
        assert!(
            !store.is_rejected(&head.repository_lineage, rejection),
            "damage to this disk is never charged to the deployment"
        );
        // And the boot that follows can still drive it: the record still names the candidate, so
        // the journal classifies as a resumable rollback.
        let situation = Situation {
            installed: store.installed().unwrap(),
            active: Some(head.release.clone()),
            journal: store.journal().unwrap(),
        };
        let derived = recovery_transaction(&situation).expect("a drivable revert");
        assert!(derived.is_rollback());
        assert!(derived.recovery_pending(Phase::RolledBack));
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
        // `converge --reason restart` and the reconciler brings the workload back up on its own time.
        let converged_at = Instant::now();
        health.reconverging(&timeouts);
        assert!(
            health.next_probe >= converged_at + timeouts.health_grace,
            "nothing has proven the re-applied release, so no probe may be recorded against it \
             until the configured grace has passed"
        );
        assert!(
            !health.last_ready,
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
            assert!(!health.last_ready);
            now += timeouts.health_interval;
        }
        health.observed(now, true, &timeouts);
        assert!(
            health.last_ready,
            "a release the hook brings back reports ready again with no agent intervention"
        );
        assert_eq!(health.next_probe, now + timeouts.health_interval);
    }

    #[tokio::test]
    async fn an_attention_hold_stops_boot_before_recovery_or_workload_changes() {
        let root = tempfile::tempdir().unwrap();
        let mut opts = options();
        opts.paths = updated::config::Paths::resolve(root.path(), root.path());
        updated::command_adapter::write_attention(
            root.path(),
            &updated_contracts::attention::Attention {
                product: "app".into(),
                receipt: "a".repeat(64),
                operation: updated_contracts::reconciler::MutationOperation::Converge,
                attempt: "b".repeat(64),
                version: "4.0.0".into(),
                message: "verify external migration".into(),
            },
        )
        .unwrap();
        // Even stale invocation cleanup must wait for the operator decision.
        let evidence = opts
            .paths
            .reconciler_state_dir("app")
            .join("invocations/evidence");
        std::fs::create_dir_all(evidence.parent().unwrap()).unwrap();
        std::fs::write(&evidence, b"keep").unwrap();
        let active = opts.paths.active_release.clone();
        let error = run(opts).await.unwrap_err();
        assert!(error.to_string().contains("operator attention required"));
        assert_eq!(std::fs::read(evidence).unwrap(), b"keep");
        assert!(!active.exists());
    }

    /// Options in the shape [`crate::options::parse_args`] produces, against a local routing
    /// repository so nothing here reaches the network.
    pub(crate) fn options() -> Options {
        use updated::config::{Paths, Routing};
        let root = crate::test_support::nonexistent_root();
        let routing = Routing {
            root: root.join("enrollment/routing"),
            base_url: crate::test_support::local_repository_base(),
            assignment: "assignments/agents/agent-test.json".into(),
            transport_timeout: Duration::from_secs(30),
            mtls: updated::tls::Identity::new(
                root.join("client.pem"),
                root.join("client.key"),
                root.join("ca.pem"),
            ),
        };
        Options {
            helper_executable: std::env::current_exe().unwrap(),
            deployment: "test".into(),
            assignment_sha256: "a".repeat(64),
            runtime_data: crate::runtime_data::RuntimeDataManager::new(
                &routing,
                &updated_contracts::dataflow::InputSelection::default(),
                &root.join("enrollment/runtime-inputs.json"),
            )
            .expect("a local repository"),
            runtime_converge_pending: false,
            paths: Paths::resolve(&root, &root.join("enrollment")),
            application: Application {
                product: "app".into(),
                channel: "stable".into(),
                install_root: root.clone(),
                input_selection: updated_contracts::dataflow::InputSelection::default(),
            },
            inputs: updated_contracts::dataflow::FileSnapshot::default(),
            routing,
            timeouts: BoundedTimeouts::new(Timeouts::default()),
            storage: runtime().storage,
            identity_renewal: IdentityRenewal {
                config: root.join("config.toml"),
                state_dir: root.join("enrollment"),
            },
        }
    }

    fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        // The shared fixture, with the one field these tests care about: an install root that
        // must not exist, so a path that escaped into a real filesystem operation would fail
        // loudly rather than write somewhere.
        updated_contracts::assignment::ManagedRuntime {
            install_root: crate::test_support::nonexistent_root(),
            ..updated_contracts::assignment::testing::runtime()
        }
    }

    /// The one bit the control plane cannot derive for itself, locked to the identity the
    /// acquisition paths actually write. A rejection is scoped by repository lineage and names
    /// either one malformed artifact or the exact failed app/provider deployment; the heartbeat
    /// has to ask the same central predicate or it can silently wait forever for impossible
    /// convergence.
    #[test]
    fn the_heartbeat_reports_a_rejection_of_exactly_the_assigned_release() {
        use updated_contracts::artifact::TargetReference;
        use updated_contracts::assignment::RepositoryAssignment;

        let assignment = RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "deployment".into(),
            metadata_url: "https://repo/metadata/".into(),
            targets_url: "https://repo/targets/".into(),
            application: TargetReference {
                path: "releases/app/2/app.bundle".into(),
                sha256: "a".repeat(64),
            },
            cold_install_fallback: false,
            release_root: serde_json::json!({}),
            runtime: runtime(),
        };
        let mut store = Store::default();
        let lineage = RepositoryLineage::from_metadata_url(&assignment.metadata_url)
            .expect("fixture metadata URL is valid");
        assert!(
            !rejects_release(&store, &lineage, &assignment),
            "a node with no rejection record claims none"
        );

        // Unrelated evidence says nothing about this assignment.
        store.reject_artifact(&lineage, &"c".repeat(64)).unwrap();
        assert!(
            !rejects_release(&store, &lineage, &assignment),
            "a rejection of OTHER bytes says nothing about the assigned release"
        );
        store
            .reject_deployment(&lineage, &assignment.application.sha256)
            .unwrap();
        assert!(rejects_release(&store, &lineage, &assignment));
        assert!(
            !store.is_rejected(&lineage, &assignment.application.sha256),
            "a failed combination does not poison either reusable artifact"
        );

        let mut malformed_artifact_store = Store::default();
        malformed_artifact_store
            .reject_artifact(&lineage, &assignment.application.sha256)
            .unwrap();
        assert!(rejects_release(
            &malformed_artifact_store,
            &lineage,
            &assignment
        ));

        // A different repository lineage is a different key: the same digest published through
        // another repository is not the release this node refused.
        let mut elsewhere = assignment.clone();
        elsewhere.metadata_url = "https://other-repo/metadata/".into();
        let elsewhere_lineage = RepositoryLineage::from_metadata_url(&elsewhere.metadata_url)
            .expect("fixture metadata URL is valid");
        assert!(!rejects_release(&store, &elsewhere_lineage, &elsewhere));
    }

    #[test]
    fn a_reassignment_converges_exactly_when_the_release_could_observe_the_change() {
        // The agent owns no process to reconfigure, so the ONLY way a changed input reaches the
        // release is another reconciler invocation. Answering "no change" leaves the node running
        // on values the assignment has replaced; answering "changed" on a cadence tweak re-converges
        // the whole fleet for nothing.
        let mut opts = options();
        let mut reinput = runtime();
        reinput.inputs = updated_contracts::dataflow::InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: ["endpoint".to_string()].into_iter().collect(),
        };
        assert!(
            !opts.runtime_is_converged(&reinput),
            "a newly resolved selection is unsettled even before its S3 fetch succeeds"
        );
        assert!(
            !opts.apply_runtime(
                &runtime(),
                updated_contracts::dataflow::FileSnapshot::default()
            ),
            "the runtime the options already hold converges nothing"
        );

        let snapshot = updated_contracts::dataflow::FileSnapshot {
            files: std::collections::BTreeMap::from([(
                "endpoint".to_string(),
                updated_contracts::dataflow::FileValue::from_bytes(
                    b"https://service.internal:8200",
                )
                .unwrap(),
            )]),
        };
        assert!(
            opts.apply_runtime(&reinput, snapshot.clone()),
            "a re-resolved input"
        );
        assert!(!opts.runtime_is_converged(&reinput));
        assert!(
            opts.apply_runtime(&reinput, snapshot.clone()),
            "a failed converge remains due when the desired snapshot is unchanged"
        );
        opts.runtime_converged();
        assert!(opts.runtime_is_converged(&reinput));
        assert!(
            !opts.apply_runtime(&reinput, snapshot.clone()),
            "only a successful converge clears the dirty state"
        );

        let mut cadence = reinput.clone();
        cadence.timeouts.check_interval_seconds = 60;
        assert!(
            !opts.apply_runtime(&cadence, snapshot),
            "a cadence change is picked up without touching the release"
        );
        assert_eq!(opts.timeouts.check_interval, Duration::from_secs(60));
    }

    #[test]
    fn every_converge_the_loop_runs_is_reason_restart() {
        // A changed input, repaired bundle, and ordinary steady-state cycle all reach the release
        // the same way: `converge --reason restart`, which is the reconciler's cue to re-converge
        // whatever it owns onto the current values. `install` is the first boot's alone.
        let source = crate::test_support::normalized_source(include_str!("main.rs"));
        let loop_body = &source[source
            .find("let flow: Result<TickFlow")
            .expect("the cycle body is one expression")..];
        // Spelled in halves so this assertion does not count itself.
        let call = concat!("reconverge_", "environment(&opts, &store, &mut health)");
        let converges = loop_body.matches(call).count();
        assert_eq!(
            converges, 3,
            "the repair, runtime reassignment, and continuous-convergence arms"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_disk_is_still_recognised_behind_a_post_commit_wrapper() {
        // `foundation::durable` wraps a failure that happens AFTER the rename landed, so the
        // durable wrapper does not roll back a pointer that already moved. Attaching that marker costs the
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
        let deadline = now + TRANSIENT_RETRY_BUDGET;

        // The exact states a candidate agent's boot recovery hits on a full state volume, a
        // read-only remount, a bad disk, and a CDN blip. None of them says anything about these
        // agent bytes, so none of them may end in a rejection by content hash.
        let node_local_transients = [
            io::Error::from(io::ErrorKind::StorageFull),
            io::Error::from(io::ErrorKind::ReadOnlyFilesystem),
            io::Error::from(io::ErrorKind::NetworkUnreachable),
            io::Error::from(io::ErrorKind::ConnectionReset),
        ];
        // EIO is the Unix raw-code case the production classifier recognises in addition to the
        // portable ErrorKind cases above. Windows has no libc errno and no corresponding branch.
        #[cfg(unix)]
        let bad_disk = Some(io::Error::from_raw_os_error(libc::EIO));
        #[cfg(not(unix))]
        let bad_disk: Option<io::Error> = None;
        for error in node_local_transients.into_iter().chain(bad_disk) {
            assert!(
                retry_after_transient(&error, now, deadline, &shutdown),
                "{error:?} is a fault of the node, so it is waited out from behind readiness"
            );
        }

        // A fault the state or the release owns is not retried at all: it is exactly as true on
        // the next attempt, and an agent that never exits is the worse failure.
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
}
