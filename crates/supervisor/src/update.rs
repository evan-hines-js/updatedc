use super::*;

pub(crate) enum Outcome {
    Committed,
    RejectedBeforeActivation,
    Deferred,
    /// A candidate failed *after* activation: it is rejected and the durable rollback journal is
    /// left in place, but the actual rollback is performed by the one rollback implementation — the
    /// boot state machine — after this disposable supervisor terminates and the guardian relaunches
    /// it. There is no in-process rollback path.
    RollbackPending,
}

#[derive(Clone, Copy)]
pub(crate) enum LifecyclePhase {
    Preflight,
    PreDrain,
    Drain,
    Prepare,
    Stop,
    /// Runs immediately before the application process is launched, on *every* launch —
    /// first install, plain restart, and update. The place for per-boot environment prep
    /// (seed a JBoss home, clear a wedged NFS mount). Fail-closed: if it fails, the app is
    /// not launched. `UPDATED_LIFECYCLE_REASON` tells the provider which kind of launch.
    PreStart,
    /// The provider's activation hand-off, run for every mode right after the built-in pointer
    /// swap (`store.activate`) and before the process is (re)launched. `stop-start` treats it as a
    /// no-op hook (the fresh process is launched in the later `Start` phase); `custom` does its
    /// program-specific work here — reload the running process in place (a SIGHUP, an exec),
    /// reuse the same directory, move files in, migrate — on top of, not instead of, the pointer
    /// swap that already made the candidate current, and is handed the live PID. Fail-closed: a
    /// failure rolls the update back.
    Activate,
    Start,
    Verify,
    Finalize,
    Rollback,
}

/// Why the application is being launched — passed to the provider as
/// `UPDATED_LIFECYCLE_REASON` so one script can branch (first-boot seeding vs. per-restart
/// cleanup vs. an update) instead of needing a hook per situation.
#[derive(Clone, Copy)]
pub(crate) enum LifecycleReason {
    Install,
    Restart,
    Update,
}

impl LifecycleReason {
    fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Restart => "restart",
            Self::Update => "update",
        }
    }
}

impl LifecyclePhase {
    fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::PreDrain => "pre-drain",
            Self::Drain => "drain",
            Self::Prepare => "prepare",
            Self::Stop => "stop",
            Self::PreStart => "pre-start",
            Self::Activate => "activate",
            Self::Start => "start",
            Self::Verify => "verify",
            Self::Finalize => "finalize",
            Self::Rollback => "rollback",
        }
    }
}

/// Crashes at a configured transaction boundary, for the e2e's crash-recovery scenarios.
/// Compiled in only under the `chaos` feature (which the e2e enables); a production build
/// has no injection points, so a stray `UPDATED_CHAOS_POINT` can never crash it. One-shot:
/// after it fires it drops a sentinel, so the relaunched supervisor recovers instead of
/// crashing again at the same boundary forever.
pub(crate) struct Chaos {
    #[cfg(feature = "chaos")]
    point: Option<String>,
    #[cfg(feature = "chaos")]
    sentinel: Option<PathBuf>,
}

impl Chaos {
    #[cfg(feature = "chaos")]
    pub(crate) fn from_env() -> Self {
        Chaos {
            point: std::env::var(env::CHAOS_POINT).ok(),
            sentinel: std::env::var(control::STATE_DIR_ENV)
                .ok()
                .map(|d| PathBuf::from(d).join("chaos-fired")),
        }
    }
    #[cfg(not(feature = "chaos"))]
    pub(crate) fn from_env() -> Self {
        Chaos {}
    }

    #[cfg(feature = "chaos")]
    pub(crate) fn crossing(&self, phase: &str) {
        if self.point.as_deref() != Some(phase) {
            return;
        }
        if let Some(sentinel) = &self.sentinel {
            if sentinel.exists() {
                return; // already crashed here once; let recovery proceed.
            }
            let _ = std::fs::write(sentinel, phase);
        }
        eprintln!("supervisor: CHAOS: exiting at boundary {phase:?}");
        std::process::exit(137);
    }

    #[cfg(not(feature = "chaos"))]
    #[inline]
    pub(crate) fn crossing(&self, _phase: &str) {}
}

/// The transaction boundaries chaos can crash at, as named constants. The crossing points
/// in [`apply_update`] and the `BOUNDARIES` list the e2e enumerates both reference these,
/// so the two cannot drift — a crossing and its list entry are the *same* string.
pub(crate) mod boundary {
    use crate::domain::TransactionPhase;

    pub const PREFLIGHT_APPLIED: &str = "preflight-applied";
    pub const PREFLIGHT_STARTED: &str = "preflight-started";
    pub const PREFLIGHT_COMPLETED: &str = "preflight-completed";
    pub const PREPARE_STARTED: &str = "prepare-started";
    pub const PREPARED: &str = "prepared";
    pub const PREPARE_APPLIED: &str = "prepare-applied";
    pub const PRE_DRAIN_STARTED: &str = "pre-drain-started";
    pub const PRE_DRAIN_APPLIED: &str = "pre-drain-applied";
    pub const DRAIN_STARTED: &str = "drain-started";
    pub const DRAINED: &str = "drained";
    pub const DRAIN_APPLIED: &str = "drain-applied";
    pub const STOP_STARTED: &str = "stop-started";
    pub const STOP_APPLIED: &str = "stop-applied";
    pub const STOPPED: &str = "stopped";
    pub const ACTIVATE_STARTED: &str = "activate-started";
    pub const CANDIDATE_POINTER_APPLIED: &str = "candidate-pointer-applied";
    pub const CANDIDATE_LIFECYCLE_APPLIED: &str = "candidate-lifecycle-applied";
    pub const CANDIDATE_ACTIVATED: &str = "candidate-activated";
    pub const CANDIDATE_STARTED: &str = "candidate-started";
    pub const START_STARTED: &str = "start-started";
    pub const CANDIDATE_START_APPLIED: &str = "candidate-start-applied";
    pub const CANDIDATE_HEALTHY: &str = "candidate-healthy";
    pub const HEALTH_STARTED: &str = "health-started";
    pub const CANDIDATE_HEALTH_APPLIED: &str = "candidate-health-applied";
    pub const FINALIZED: &str = "finalized";
    pub const FINALIZE_STARTED: &str = "finalize-started";
    pub const FINALIZE_APPLIED: &str = "finalize-applied";
    pub const COMMITTED: &str = "committed";
    pub const COMMIT_STARTED: &str = "commit-started";
    pub const COMMIT_APPLIED: &str = "commit-applied";
    pub const ROLLBACK_STARTED: &str = "rollback-started";
    pub const ROLLBACK_STOP_STARTED: &str = "rollback-stop-started";
    pub const ROLLBACK_STOP_APPLIED: &str = "rollback-stop-applied";
    pub const ROLLBACK_STOPPED: &str = "rollback-stopped";
    pub const ROLLBACK_ACTIVATE_STARTED: &str = "rollback-activate-started";
    pub const PREDECESSOR_POINTER_APPLIED: &str = "predecessor-pointer-applied";
    pub const PREDECESSOR_LIFECYCLE_APPLIED: &str = "predecessor-lifecycle-applied";
    pub const PREDECESSOR_ACTIVATED: &str = "predecessor-activated";
    pub const PREDECESSOR_START_APPLIED: &str = "predecessor-start-applied";
    pub const PREDECESSOR_STARTED: &str = "predecessor-started";
    pub const ROLLBACK_START_STARTED: &str = "rollback-start-started";
    pub const PREDECESSOR_HEALTH_APPLIED: &str = "predecessor-health-applied";
    pub const PREDECESSOR_HEALTHY: &str = "predecessor-healthy";
    pub const ROLLBACK_HEALTH_STARTED: &str = "rollback-health-started";
    pub const ROLLBACK_FINALIZE_STARTED: &str = "rollback-finalize-started";
    pub const ROLLBACK_ADAPTER_APPLIED: &str = "rollback-lifecycle-applied";
    pub const ROLLED_BACK: &str = "rolled-back";
    pub const ABORTED: &str = "aborted";

    pub fn durable_phase(phase: TransactionPhase) -> &'static str {
        match phase {
            TransactionPhase::PreflightStarted => PREFLIGHT_STARTED,
            TransactionPhase::PreflightCompleted => PREFLIGHT_COMPLETED,
            TransactionPhase::PrepareStarted => PREPARE_STARTED,
            TransactionPhase::Prepared => PREPARED,
            TransactionPhase::PreDrainStarted => PRE_DRAIN_STARTED,
            TransactionPhase::DrainStarted => DRAIN_STARTED,
            TransactionPhase::Drained => DRAINED,
            TransactionPhase::StopStarted => STOP_STARTED,
            TransactionPhase::Stopped => STOPPED,
            TransactionPhase::ActivateStarted => ACTIVATE_STARTED,
            TransactionPhase::CandidateActivated => CANDIDATE_ACTIVATED,
            TransactionPhase::CandidateVerified => "on-launch-candidate-verified",
            TransactionPhase::StartStarted => START_STARTED,
            TransactionPhase::CandidateStarted => CANDIDATE_STARTED,
            TransactionPhase::HealthStarted => HEALTH_STARTED,
            TransactionPhase::CandidateHealthy => CANDIDATE_HEALTHY,
            TransactionPhase::FinalizeStarted => FINALIZE_STARTED,
            TransactionPhase::Finalized => FINALIZED,
            TransactionPhase::CommitStarted => COMMIT_STARTED,
            TransactionPhase::Committed => COMMITTED,
            TransactionPhase::RollbackStarted => ROLLBACK_STARTED,
            TransactionPhase::RollbackStopStarted => ROLLBACK_STOP_STARTED,
            TransactionPhase::RollbackStopped => ROLLBACK_STOPPED,
            TransactionPhase::RollbackActivateStarted => ROLLBACK_ACTIVATE_STARTED,
            TransactionPhase::PredecessorActivated => PREDECESSOR_ACTIVATED,
            TransactionPhase::RollbackStartStarted => ROLLBACK_START_STARTED,
            TransactionPhase::PredecessorStarted => PREDECESSOR_STARTED,
            TransactionPhase::RollbackHealthStarted => ROLLBACK_HEALTH_STARTED,
            TransactionPhase::PredecessorHealthy => PREDECESSOR_HEALTHY,
            TransactionPhase::RollbackFinalizeStarted => ROLLBACK_FINALIZE_STARTED,
            TransactionPhase::RolledBack => ROLLED_BACK,
            TransactionPhase::Aborted => ABORTED,
            TransactionPhase::Started => "on-launch-started",
        }
    }
}

/// The ordered boundary list, emitted by `supervisor --list-chaos-boundaries` so the e2e
/// drives exactly these — one source of truth across the crate boundary (the e2e runs the
/// supervisor as a subprocess and cannot share a `const`).
#[cfg(any(feature = "chaos", test))]
pub(crate) const BOUNDARIES: &[&str] = &[
    boundary::PREFLIGHT_STARTED,
    boundary::PREFLIGHT_APPLIED,
    boundary::PREFLIGHT_COMPLETED,
    boundary::PREPARE_STARTED,
    boundary::PREPARE_APPLIED,
    boundary::PREPARED,
    boundary::PRE_DRAIN_STARTED,
    boundary::PRE_DRAIN_APPLIED,
    boundary::DRAIN_STARTED,
    boundary::DRAIN_APPLIED,
    boundary::DRAINED,
    boundary::STOP_STARTED,
    boundary::STOP_APPLIED,
    boundary::STOPPED,
    boundary::ACTIVATE_STARTED,
    boundary::CANDIDATE_POINTER_APPLIED,
    boundary::CANDIDATE_LIFECYCLE_APPLIED,
    boundary::CANDIDATE_ACTIVATED,
    boundary::START_STARTED,
    boundary::CANDIDATE_START_APPLIED,
    boundary::CANDIDATE_STARTED,
    boundary::HEALTH_STARTED,
    boundary::CANDIDATE_HEALTH_APPLIED,
    boundary::CANDIDATE_HEALTHY,
    boundary::FINALIZE_STARTED,
    boundary::FINALIZE_APPLIED,
    boundary::FINALIZED,
    boundary::COMMIT_STARTED,
    boundary::COMMIT_APPLIED,
    boundary::COMMITTED,
];

#[cfg(any(feature = "chaos", test))]
pub(crate) const ROLLBACK_BOUNDARIES: &[&str] = &[
    boundary::ROLLBACK_STARTED,
    boundary::ROLLBACK_STOP_STARTED,
    boundary::ROLLBACK_STOP_APPLIED,
    boundary::ROLLBACK_STOPPED,
    boundary::ROLLBACK_ACTIVATE_STARTED,
    boundary::PREDECESSOR_POINTER_APPLIED,
    boundary::PREDECESSOR_LIFECYCLE_APPLIED,
    boundary::PREDECESSOR_ACTIVATED,
    boundary::ROLLBACK_START_STARTED,
    boundary::PREDECESSOR_START_APPLIED,
    boundary::PREDECESSOR_STARTED,
    boundary::ROLLBACK_HEALTH_STARTED,
    boundary::PREDECESSOR_HEALTH_APPLIED,
    boundary::PREDECESSOR_HEALTHY,
    boundary::ROLLBACK_FINALIZE_STARTED,
    boundary::ROLLBACK_ADAPTER_APPLIED,
    boundary::ROLLED_BACK,
];

#[cfg(any(feature = "chaos", test))]
pub(crate) const ABORT_BOUNDARIES: &[&str] = &[boundary::ABORTED];

// ============================ the live-application port ============================
//
// What the transaction drives on the *live* side — the running application and its
// readiness — behind a port, exactly as [`Store`] ports the durable side. The production
// [`DefaultProvider`] performs the configured `Restart` mode over the guardian-owned [`App`]; a
// test fake scripts control outcomes and health, so every fault path of [`apply_update`] is
// provable without a guardian, an HTTP server, or a real process.

/// Bring a staged release into service — the activation hand-off moments. The port the transaction
/// drives; the sole restart abstraction (the `Restart` mode is data the [`DefaultProvider`]
/// lifecycle acts on). A post-activation failure does not roll back in-process: the transaction
/// rejects the candidate, leaves a durable rollback journal, and the supervisor terminates so boot
/// recovery performs the one rollback path.
/// How the built-in drain waits, after readiness is withdrawn and before the running release is
/// stopped, so the load balancer has removed this node from rotation first (no in-flight request
/// lands on a stopping process).
pub(crate) enum DrainHold {
    /// Stop immediately — a `custom` deployment (its provider owns the drain), or a managed one
    /// that set the hold to zero.
    None,
    /// Hold up to this long — a bounded ceiling on how long we wait after withdrawing readiness
    /// before stopping the running release. Today it is a fixed sleep; a future increment can let
    /// the intermediary's signed drain acknowledgement (`ManagedStatus.ready`) end the wait early.
    Bounded(Duration),
}

pub(crate) trait DeploymentProvider {
    /// Change whether external traffic may reach the managed application.
    fn traffic_ready(&mut self, ready: bool) -> io::Result<()>;
    /// The drain hold policy: how long to wait, after readiness is withdrawn, before stopping.
    fn drain_hold(&self) -> DrainHold;
    /// Invoke the optional operator-owned lifecycle provider.
    fn lifecycle(
        &mut self,
        phase: LifecyclePhase,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Stop the predecessor when the activation strategy requires a process stop.
    fn stop(&mut self) -> io::Result<()>;
    /// Apply the selected release to the surrounding service environment.
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Start the selected release when activation requires a fresh process.
    fn start(&mut self) -> io::Result<()>;
    /// Whether readiness must additionally prove the running version (an in-place reload keeps
    /// the launch token, so the token alone cannot identify the reloaded image).
    fn requires_version_proof(&self) -> bool;
}

/// Probe the release to readiness — the health-check provider if the release ships one, else
/// the HTTP readiness URL, else simply surviving the grace window. `expected_version` is set
/// only for an in-place reload, where the launch token cannot distinguish the running image.
/// The future is not `Send`-bound: the update loop is driven by `block_on` on one thread, never
/// spawned, so the transaction never crosses threads (as before this port existed).
pub(crate) trait Health {
    fn became_healthy(
        &self,
        expected_version: Option<&str>,
    ) -> impl std::future::Future<Output = bool>;
}

/// The production tower: `reloads_in_place` selects the process seam over the
/// guardian-owned [`App`], the lifecycle `phases` provider runs the operator hooks, and
/// `Health` is the readiness signal (health-check provider if present, else the HTTP probe).
pub(crate) struct DefaultProvider<'a> {
    app: &'a mut App,
    opts: &'a Options,
    /// Whether activation reloads a still-running process *in place* (a SIGHUP/exec/vendor reload)
    /// rather than the guardian stop-starting it. When true the guardian's stop/start/traffic
    /// operations are no-ops (the operator's `activate` script owns the transition and drain), the
    /// `activate` hook gets the live PID to signal, and readiness must prove the version (the
    /// reloaded process keeps its launch token). When false the guardian stop-starts a fresh
    /// process. The guardian holds the process either way.
    reloads_in_place: bool,
    /// The release's health-check provider, if it ships one — the readiness signal that
    /// replaces the HTTP probe. Resolved from the provider set alongside `phases`.
    healthcheck: Option<&'a updated::state::ProviderRelease>,
    phases: LoadedPhaseProvider<'a>,
}

/// One lifecycle protocol with two loading strategies. The default implementation is
/// statically linked into this supervisor; an external implementation is the same
/// protocol resolved from a signed bundle. Callers never branch around the provider.
enum LoadedPhaseProvider<'a> {
    BuiltIn(BuiltInPhases),
    External {
        release: &'a updated::state::ProviderRelease,
        opts: &'a Options,
    },
}

struct BuiltInPhases;

impl BuiltInPhases {
    fn invoke(&self, _invocation: LifecycleInvocation<'_>) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> LoadedPhaseProvider<'a> {
    fn load(
        opts: &'a Options,
        external: Option<&'a updated::state::ProviderRelease>,
    ) -> Self {
        match external {
            Some(release) => Self::External { release, opts },
            None => Self::BuiltIn(BuiltInPhases),
        }
    }

    fn invoke(&self, invocation: LifecycleInvocation<'_>) -> io::Result<()> {
        match self {
            Self::BuiltIn(provider) => provider.invoke(invocation),
            Self::External { release, opts } => run_lifecycle_command(release, opts, invocation),
        }
    }
}

pub(crate) fn invoke_deployment_provider(
    external: Option<&updated::state::ProviderRelease>,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    LoadedPhaseProvider::load(opts, external).invoke(invocation)
}

/// Launch a fresh application, running the operator's `pre-start` hook first — the one
/// launch path for a first install or a plain restart. The hook gets
/// `UPDATED_LIFECYCLE_REASON` (`install`/`restart`) so one script can do per-boot prep
/// (seed a JBoss home, clear a wedged NFS mount) and tell a first boot from a restart.
///
/// `reason` is `None` when the boot is resuming an interrupted transaction: recovery replays
/// only that transaction's own minimal, idempotent steps, so the per-boot hook is skipped and
/// the application is launched directly.
///
/// Fail-closed: if the hook fails the application is *not* launched — the error propagates
/// and the guardian retries the whole tower with backoff. The built-in provider is a no-op,
/// so a node with no operator hook launches exactly as before.
pub(crate) fn launch_with_pre_start(
    guardian: Guardian,
    opts: &Options,
    store: &dyn Store,
    reason: Option<LifecycleReason>,
) -> io::Result<App> {
    if let Some(reason) = reason {
        if let updated::state::Installed::Present(installed) = store.installed() {
            let installed = *installed;
            let release = installed.release;
            let lifecycle = installed.lifecycle;
            // Pre-start is a per-boot environment hook, run on every launch. Release placement
            // (including Custom's provider hook) already happened durably — in the install
            // machine on a first boot, in the update transaction on an upgrade — so this path
            // never places; it only prepares the environment before the launch.
            invoke_deployment_provider(
                lifecycle.as_deref(),
                opts,
                LifecycleInvocation {
                    phase: LifecyclePhase::PreStart,
                    reason,
                    id: "boot",
                    pid: None,
                    candidate: &release,
                    predecessor: &release,
                },
            )?;
        }
    }
    crate::app::start(guardian, opts)
}

impl<'a> DefaultProvider<'a> {
    /// The built-in provider is part of this binary, never an independently upgraded
    /// artifact. Exposing this constant prevents inventing a second version source.
    pub(crate) const VERSION: &'static str = SELF_VERSION;

    pub(crate) fn new(
        app: &'a mut App,
        opts: &'a Options,
        lifecycle: Option<&'a updated::state::ProviderRelease>,
        healthcheck: Option<&'a updated::state::ProviderRelease>,
    ) -> Self {
        DefaultProvider {
            app,
            opts,
            reloads_in_place: reloads_in_place(opts, lifecycle),
            healthcheck,
            phases: LoadedPhaseProvider::load(opts, lifecycle),
        }
    }

    /// The PID handed to the hooks / used for health: the guardian's launched PID (the guardian
    /// always holds the process).
    fn hook_pid(&self) -> Option<u32> {
        Some(self.app.pid())
    }
}

/// Whether this release **reloads in place** at activation — i.e. its lifecycle provider ships an
/// `activate` script. When it does, the guardian does not restart the process; the operator's
/// `activate` script reloads it in place and readiness proves the version. Absent (or no lifecycle
/// provider at all) → the guardian **restarts** the process (stop-start). A resolve failure defaults
/// to restart; the corrupt bundle then fails closed when its first phase runs.
pub(crate) fn reloads_in_place(
    opts: &Options,
    lifecycle: Option<&updated::state::ProviderRelease>,
) -> bool {
    lifecycle
        .and_then(|release| {
            updated::provider::BundleStore::for_lifecycle(&opts.paths)
                .resolve(&release.release)
                .ok()
        })
        .is_some_and(|resolved| resolved.activate.is_some())
}

impl DeploymentProvider for DefaultProvider<'_> {
    fn traffic_ready(&mut self, ready: bool) -> io::Result<()> {
        if self.reloads_in_place {
            // A reload keeps serving; the operator's script owns readiness rotation.
            return Ok(());
        }
        self.app
            .guardian
            .traffic_ready(ready)
            .map_err(io::Error::other)
    }
    fn drain_hold(&self) -> DrainHold {
        if self.reloads_in_place {
            // The operator's `activate`/drain scripts own the drain end to end.
            return DrainHold::None;
        }
        match self.opts.timeouts.drain_hold {
            Some(hold) if hold.is_zero() => DrainHold::None,
            Some(hold) => DrainHold::Bounded(hold),
            // An unset drain hold is *no* hold — deterministic and never a stall. (An indefinite
            // "wait for the intermediary's drain-ack" mode is future work; see config docs.)
            None => DrainHold::None,
        }
    }
    fn lifecycle(
        &mut self,
        phase: LifecyclePhase,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        // The hook is told the current process PID (UPDATED_CHILD_PID) — the process provider's
        // for a custom release, the guardian's otherwise. It is informational, never a branch.
        let pid = self.hook_pid();
        self.phases.invoke(LifecycleInvocation {
            phase,
            reason: LifecycleReason::Update,
            id: lifecycle_attempt_id,
            pid,
            candidate,
            predecessor,
        })
    }
    fn stop(&mut self) -> io::Result<()> {
        if self.reloads_in_place {
            // Nothing to stop: the process keeps running and is reloaded in place at activation.
            return Ok(());
        }
        stop(&mut self.app.guardian, &self.opts.paths.app_token)
    }
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        // The managed default stopped the process before activation, so its hook gets no PID; a
        // provider-driven reload kept the process running and reloads it in place, so its hook
        // gets the live PID to signal.
        let pid = if self.reloads_in_place {
            self.hook_pid()
        } else {
            None
        };
        self.phases.invoke(LifecycleInvocation {
            phase: LifecyclePhase::Activate,
            reason: LifecycleReason::Update,
            id: lifecycle_attempt_id,
            pid,
            candidate,
            predecessor,
        })
    }
    fn start(&mut self) -> io::Result<()> {
        if self.reloads_in_place {
            // The process was never stopped; the reload at activation brought the new version up.
            return Ok(());
        }
        self.app.launch(self.opts)
    }
    fn requires_version_proof(&self) -> bool {
        self.reloads_in_place
    }
}

impl Health for DefaultProvider<'_> {
    async fn became_healthy(&self, expected_version: Option<&str>) -> bool {
        // The health-check provider, when the release ships one, is the readiness signal and
        // replaces the HTTP probe; otherwise the HTTP readiness URL, otherwise surviving the
        // grace window. A probe-infrastructure error (a client that will not even build, a
        // provider that cannot be resolved) is a health failure like any other: fail closed to
        // a rollback rather than propagate.
        if let Some(healthcheck) = self.healthcheck {
            // The provider actively probes the running service, so it identifies the image
            // directly and needs no version header from it.
            return became_healthy_via_provider(
                healthcheck,
                self.opts,
                self.hook_pid(),
                self.opts.timeouts.health_grace,
                self.opts.timeouts.health_successes,
                self.opts.timeouts.health_interval,
            )
            .await;
        }
        became_healthy(
            self.app,
            self.opts.timeouts.health_grace,
            self.opts
                .application
                .health_check_url(updated::config::HealthCheckKind::Readiness),
            expected_version,
            self.opts.timeouts.health_successes,
            self.opts.timeouts.health_interval,
        )
        .await
        .unwrap_or(false)
    }
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// live-application ([`DeploymentProvider`] + [`Health`]) ports.
pub(crate) async fn apply_update<T: DeploymentProvider + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
    candidate_repository_lineage: updated::state::RepositoryLineage,
    lifecycle: Option<updated::state::ProviderRelease>,
    healthcheck: Option<updated::state::ProviderRelease>,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live supervisor must never mutate
    // recovery evidence or restore an executable underneath a guardian-owned process.
    // Any transaction error terminates this disposable supervisor; bootstrap keeps the
    // application alive and relaunches us through the one recovery path.
    if store.journal()?.is_some() {
        return Err(io::Error::other(
            "an unreconciled update journal requires supervisor restart",
        ));
    }

    let installed = match store.installed() {
        Installed::Present(state) => state,
        _ => return Err(io::Error::other("a verified installed release is required")),
    };
    let chaos = Chaos::from_env();
    let mut tx = Transaction {
        id: updated::rand::token()?,
        kind: updated::transaction::Kind::Supervised,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        previous_repository_lineage: installed.repository_lineage.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.to_string(),
        candidate_repository_lineage: candidate_repository_lineage.clone(),
        candidate_rejection_required: false,
        // These fields drive ROLLBACK recovery (restoring the predecessor), so they carry the
        // PREDECESSOR's own signed providers — app and providers are one signed unit, and a revert
        // must gate/watch the old release with the old hooks, not the candidate's. The forward path
        // runs the candidate through the `tower`, never these fields; the candidate's providers
        // become the new head's providers at commit below. This keeps the journal-driven recovery
        // (an in-process rollback that crashed) consistent with the pending-driven one, which
        // already carries the predecessor's providers.
        lifecycle: installed.lifecycle.clone(),
        healthcheck: installed.healthcheck.clone(),
        phase: TransactionPhase::PreflightStarted,
    };
    persist_transaction(store, &tx)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Preflight,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} failed lifecycle preflight ({error}); the running release was not touched",
            candidate.version
        ));
        require_candidate_rejection(store, &mut tx)?;
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::RejectedBeforeActivation);
    }
    chaos.crossing(boundary::PREFLIGHT_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::PreflightCompleted)?;

    advance_transaction(store, &mut tx, TransactionPhase::PrepareStarted)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Prepare,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} was deferred while preparing its environment ({error}); the running release remains active",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::PREPARE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Prepared)?;

    // Pre-drain: custom logic *before* we withdraw from traffic — e.g. tell the app to
    // begin shedding work — while the predecessor is still serving. Nothing has changed
    // yet, so a failure here defers cleanly. No-op when the provider defines no pre-drain
    // phase.
    advance_transaction(store, &mut tx, TransactionPhase::PreDrainStarted)?;
    if let Err(error) =
        tower.lifecycle(LifecyclePhase::PreDrain, &tx.id, candidate, &installed.release)
    {
        warn(&format!(
            "candidate {} was deferred during pre-drain ({error}); the running release remains active",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::PRE_DRAIN_APPLIED);

    // Built-in drain: the guardian flips its readiness probe to unready and only
    // acknowledges once its probe machine is in the drained state — that acknowledgement
    // is the go-ahead. We never stop the running binary until it returns, so the node is
    // out of readiness before switchover.
    tower.traffic_ready(false)?;
    advance_transaction(store, &mut tx, TransactionPhase::DrainStarted)?;

    // Built-in drain hold: having withdrawn readiness, wait for the load balancer to actually
    // remove this node before we stop the running release — otherwise an in-flight request lands
    // on a stopping process (the downtime a bare readiness flip leaves when endpoint removal lags
    // the switchover). Bounded is a ceiling; a `custom` deployment and an unset hold wait nothing
    // here (the custom Drain hook owns it, or the operator opted out).
    match tower.drain_hold() {
        DrainHold::None => {}
        DrainHold::Bounded(hold) => tokio::time::sleep(hold).await,
    }

    // Post-drain: custom logic *after* we are unready but *before* switchover — e.g. wait
    // for the orchestrator to observe the failed probe and stop routing, or for in-flight
    // connections to finish. Must run to completion before the predecessor is stopped.
    if let Err(error) =
        tower.lifecycle(LifecyclePhase::Drain, &tx.id, candidate, &installed.release)
    {
        warn(&format!(
            "candidate {} was deferred while draining ({error}); the running release remains active",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::DRAIN_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Drained)?;

    advance_transaction(store, &mut tx, TransactionPhase::StopStarted)?;
    if let Err(error) = tower.lifecycle(LifecyclePhase::Stop, &tx.id, candidate, &installed.release)
    {
        warn(&format!(
            "candidate {} was deferred before stopping its predecessor ({error})",
            candidate.version
        ));
        // Stop is the last pre-activation boundary. Treat a provider failure as a
        // deterministic rejection, not a defer: otherwise the scheduler immediately
        // retries the same candidate and replays the provider's side effects forever.
        require_candidate_rejection(store, &mut tx)?;
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::RejectedBeforeActivation);
    }
    tower.stop()?;
    chaos.crossing(boundary::STOP_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Stopped)?;

    advance_transaction(store, &mut tx, TransactionPhase::ActivateStarted)?;
    if let Err(e) = store.activate(candidate) {
        warn(&format!("release activation failed before commit ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_POINTER_APPLIED);

    if let Err(e) = tower.activate(&tx.id, candidate, &tx.previous_release) {
        warn(&format!("activating the new version failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_LIFECYCLE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateActivated)?;
    advance_transaction(store, &mut tx, TransactionPhase::StartStarted)?;
    if let Err(e) = tower.start() {
        warn(&format!("starting the new version failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    if let Err(e) = tower.lifecycle(LifecyclePhase::Start, &tx.id, candidate, &installed.release) {
        warn(&format!("candidate start provider phase failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_START_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateStarted)?;

    advance_transaction(store, &mut tx, TransactionPhase::HealthStarted)?;
    // An in-place reload keeps the launch token, so readiness must also prove the candidate's
    // version; a fresh launch's token already identifies it.
    let version_proof = tower
        .requires_version_proof()
        .then_some(candidate.version.as_str());
    if !tower.became_healthy(version_proof).await {
        return reject_then_recover(store, &mut tx);
    }
    if let Err(e) = tower.lifecycle(
        LifecyclePhase::Verify,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!("candidate verify provider phase failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_HEALTH_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateHealthy)?;

    advance_transaction(store, &mut tx, TransactionPhase::FinalizeStarted)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Finalize,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} failed lifecycle finalization ({error})",
            candidate.version
        ));
        // Finalization is part of activation: a failed hook must not be treated as a
        // transient defer, or the scheduler will immediately replay the same transaction
        // and its side effects. Persist rejection before restoring the predecessor.
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::FINALIZE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Finalized)?;

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal reactivates the predecessor.
    let pending = Some(Pending {
        lifecycle_attempt_id: tx.id.clone(),
        previous_release: installed.release,
        previous_archive_sha256: installed.archive_sha256,
        previous_repository_lineage: installed.repository_lineage,
        committed_at: now_unix(),
        // The rollback restores the *predecessor*, so it must carry the *predecessor's own* signed
        // providers (app + providers are one signed unit), not the candidate's. At the assigned head
        // these are the same set; across a provider-set revision in this update they differ, and
        // reverting the old release with the new providers would gate/watch it with the wrong hooks.
        lifecycle: installed.lifecycle,
        healthcheck: installed.healthcheck,
    });
    advance_transaction(store, &mut tx, TransactionPhase::CommitStarted)?;
    store.commit_installed(&InstalledState {
        repository_lineage: candidate_repository_lineage,
        release: candidate.clone(),
        archive_sha256: candidate_archive_sha256.to_string(),
        // The candidate's own providers are now the installed release's providers; persist them so
        // pre-start, health gating, and PID watching can run them on the next boot. (These are the
        // candidate providers passed in — `tx.lifecycle/healthcheck/process` hold the *predecessor's*
        // now, for rollback.)
        lifecycle: lifecycle.map(Box::new),
        healthcheck: healthcheck.map(Box::new),
        pending,
        // An update always has a proven predecessor: its failure recovery is this state machine's
        // rollback, never an ordered-fallback descent, so the new head commits already confirmed.
        confirmed: true,
    })?;
    chaos.crossing(boundary::COMMIT_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Committed)?;
    // The update is durable now: the active pointer and installed state (with its
    // pending intent) is committed. Failing to delete the spent journal must NOT report the
    // transaction as failed — that would leave the loop's in-memory state stale (still the
    // old version, not pending) while disk records the new one, letting a second update
    // start over this unconfirmed one. Return Committed and let recovery remove the journal
    // (it resolves as already-committed).
    if let Err(e) = store.clear_journal() {
        warn(&format!(
            "update committed but clearing its journal failed ({e}); recovery will remove it"
        ));
    }
    tower.traffic_ready(true)?;
    Ok(Outcome::Committed)
}

/// Undo operator-side work when neither the active release nor its process changed.
/// Every pre-activation exit uses this state-machine path so an interrupted lifecycle
/// rollback remains recoverable through the ordinary boot journal.
fn abort_before_activation<T: DeploymentProvider>(
    tower: &mut T,
    store: &mut dyn Store,
    tx: &mut Transaction,
) -> io::Result<()> {
    advance_transaction(store, tx, TransactionPhase::RollbackStarted)?;
    tower.lifecycle(
        LifecyclePhase::Rollback,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    advance_transaction(store, tx, TransactionPhase::Aborted)?;
    store.clear_journal()?;
    tower.traffic_ready(true)
}

/// Persist the rejection decision before applying it. If the process dies in the gap,
/// boot recovery replays the idempotent rejection from the transaction rather than
/// forgetting why rollback began and selecting the same bad archive again.
fn require_candidate_rejection(store: &mut dyn Store, tx: &mut Transaction) -> io::Result<()> {
    if !tx.candidate_rejection_required {
        tx.candidate_rejection_required = true;
        store.write_journal(tx)?;
    }
    store.reject(
        &tx.candidate_repository_lineage,
        &tx.candidate_archive_sha256,
    )
}

/// Reject the failed candidate and hand the rollback to the boot state machine — the single
/// rollback implementation. Every post-activation failure ends here: the candidate is activated
/// (and possibly still running) but failed, so this records the rejection and leaves the durable
/// journal for boot recovery to complete on the next supervisor start. A supervisor restart is
/// cheap; the guardian keeps the (failed) application alive across it, and the freshly-booted
/// supervisor stops the candidate and restores the predecessor with the predecessor's *own*
/// providers (carried in the transaction). Rolling back here in-process would be a second rollback
/// path to keep in lockstep with boot recovery — and, because a live supervisor runs the candidate's
/// tower, it would gate the restored predecessor with the *candidate's* health provider. One path,
/// one set of providers, no divergence.
fn reject_then_recover(store: &mut dyn Store, tx: &mut Transaction) -> io::Result<Outcome> {
    require_candidate_rejection(store, tx)?;
    Ok(Outcome::RollbackPending)
}

pub(crate) fn advance_transaction(
    store: &mut dyn Store,
    tx: &mut Transaction,
    phase: TransactionPhase,
) -> io::Result<()> {
    tx.advance(phase)?;
    persist_transaction(store, tx)
}

pub(crate) fn persist_transaction(store: &mut dyn Store, tx: &Transaction) -> io::Result<()> {
    store.write_journal(tx)?;
    Chaos::from_env().crossing(boundary::durable_phase(tx.phase));
    Ok(())
}

/// Invoke the single operator lifecycle provider with a stable phase and transaction
/// identity. Commands are direct argv, never shell text. A bounded wait prevents a
/// wedged enterprise integration from wedging the updater forever.
pub(crate) struct LifecycleInvocation<'a> {
    pub(crate) phase: LifecyclePhase,
    pub(crate) reason: LifecycleReason,
    pub(crate) id: &'a str,
    pub(crate) pid: Option<u32>,
    pub(crate) candidate: &'a updated::bundle::ReleaseId,
    pub(crate) predecessor: &'a updated::bundle::ReleaseId,
}

pub(crate) fn run_lifecycle_command(
    lifecycle: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    let LifecycleInvocation {
        phase,
        reason,
        id: lifecycle_attempt_id,
        pid,
        candidate,
        predecessor,
    } = invocation;
    let resolved =
        updated::provider::BundleStore::for_lifecycle(&opts.paths).resolve(&lifecycle.release)?;
    if resolved.product != lifecycle.product {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged lifecycle manifest has the wrong product",
        ));
    }
    let timeout = Duration::from_millis(lifecycle.timeout_millis);
    let phase_name = phase.name();
    let app_provider = updated::provider::BundleStore::for_app(&opts.paths);
    let candidate_dir = app_provider.location(candidate);
    let predecessor_dir = app_provider.location(predecessor);
    // The activate hook runs the provider's `activate` (reload) script and the rollback hook its
    // `rollback` script when the bundle declares them; every other hook — and a provider that ships
    // neither — runs the forward `program`. The phase still rides in `UPDATED_LIFECYCLE_PHASE`, so a
    // dedicated script can branch too.
    let program = match phase {
        LifecyclePhase::Activate if resolved.activate.is_some() => resolved.activate.unwrap(),
        LifecyclePhase::Rollback if resolved.rollback.is_some() => resolved.rollback.unwrap(),
        _ => resolved.program,
    };
    let mut cmd = Command::new(program);
    cmd.args(&lifecycle.args)
        .current_dir(&resolved.cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .env(env::LIFECYCLE_PHASE, phase_name)
        .env(env::LIFECYCLE_REASON, reason.name())
        .env(env::LIFECYCLE_ATTEMPT_ID, lifecycle_attempt_id)
        .env(env::INSTALL_ROOT, &opts.paths.install_root)
        .env(env::CANDIDATE, &candidate_dir)
        .env(env::PREDECESSOR, &predecessor_dir)
        .env(env::CANDIDATE_VERSION, &candidate.version)
        .env(env::PREDECESSOR_VERSION, &predecessor.version);
    if let Some(pid) = pid {
        cmd.env(env::CHILD_PID, pid.to_string());
    } else {
        cmd.env_remove(env::CHILD_PID);
    }
    // A wrapper commonly waits on vendor CLIs, curl, or mount helpers. Run it as a
    // contained tree (Unix process group / Windows job object) so a timeout takes the
    // whole tree down, not just the shell — leaving the foreground operation orphaned.
    // The platform mechanism lives in `foundation::process`, not inlined here.
    let mut child = foundation::process::ContainedChild::spawn(cmd)?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "lifecycle timeout is too large",
        )
    })?;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "lifecycle {phase_name} exited with {status}"
                )))
            };
        }
        if Instant::now() >= deadline {
            child.kill_tree()?;
            child.wait()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "lifecycle {phase_name} exceeded its {}s timeout",
                    timeout.as_secs_f64()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Run the health-check provider once. Exit 0 = healthy; a non-zero exit, a timeout, or any
/// resolve/spawn error = unhealthy. Unlike a lifecycle phase, an unhealthy result is a normal
/// outcome, not an error — the caller folds it into the readiness decision (fail closed). The
/// provider is handed `UPDATED_INSTALL_ROOT` and, when the supervisor tracks one,
/// `UPDATED_CHILD_PID`, so a script can probe the exact running process. This single probe is
/// the steady-state readiness/liveness signal; startup gating layers grace/successes on top of it.
pub(crate) fn run_healthcheck_command(
    healthcheck: &updated::state::ProviderRelease,
    opts: &Options,
    pid: Option<u32>,
) -> bool {
    run_provider_probe(healthcheck, opts, false, |cmd| {
        if let Some(pid) = pid {
            cmd.env(env::CHILD_PID, pid.to_string());
        }
    })
    .0
}

/// Run a signed provider CLI once with a bounded wait, returning whether it exited 0 and — when
/// `capture_stdout` — its stdout (capped, so a provider cannot flood memory). A resolve, product,
/// or spawn failure and a timeout all read as a non-success with no output; the timed-out tree is
/// killed. The CLI gets a clean environment with `UPDATED_INSTALL_ROOT` plus whatever `configure`
/// adds. Shared by the health-check and process providers, which differ only in how they read
/// the result.
fn run_provider_probe(
    provider: &updated::state::ProviderRelease,
    opts: &Options,
    capture_stdout: bool,
    configure: impl FnOnce(&mut Command),
) -> (bool, Option<String>) {
    let resolved = match updated::provider::BundleStore::for_lifecycle(&opts.paths)
        .resolve(&provider.release)
    {
        Ok(resolved) if resolved.product == provider.product => resolved,
        _ => return (false, None),
    };
    let Some(deadline) = Instant::now().checked_add(Duration::from_millis(provider.timeout_millis))
    else {
        return (false, None);
    };
    let mut cmd = Command::new(resolved.program);
    cmd.args(&provider.args)
        .current_dir(&resolved.cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .env(env::INSTALL_ROOT, &opts.paths.install_root);
    if capture_stdout {
        cmd.stdout(std::process::Stdio::piped());
    }
    configure(&mut cmd);
    let Ok(mut child) = foundation::process::ContainedChild::spawn(cmd) else {
        return (false, None);
    };
    let stdout = if capture_stdout { child.take_stdout() } else { None };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return (false, None);
                }
                return (true, stdout.and_then(read_first_line));
            }
            Ok(None) => {}
            Err(_) => return (false, None),
        }
        if Instant::now() >= deadline {
            let _ = child.kill_tree();
            let _ = child.wait();
            return (false, None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read the first newline-terminated line of a child's stdout, capped at 64 KiB. Only the first
/// line is read (not to EOF) so a provider that forks a daemon inheriting the pipe cannot wedge
/// the read waiting for a close that never comes; the cap bounds a provider that never emits a
/// newline. The provider contract is therefore: print the PID followed by a newline, promptly.
fn read_first_line(stdout: std::process::ChildStdout) -> Option<String> {
    use std::io::{BufRead, Read};
    let mut line = String::new();
    std::io::BufReader::new(stdout.take(64 * 1024))
        .read_line(&mut line)
        .ok()?;
    Some(line)
}

/// Readiness via the health-check provider: the provider stands in for the HTTP probe, and the
/// same grace/successes/interval machinery gates it — a run of consecutive healthy exits within
/// the grace window. Mirrors [`crate::app::became_healthy`]'s loop so a provider-gated release
/// and a URL-gated one share identical readiness semantics.
pub(crate) async fn became_healthy_via_provider(
    healthcheck: &updated::state::ProviderRelease,
    opts: &Options,
    pid: Option<u32>,
    grace: Duration,
    successes: u32,
    interval: Duration,
) -> bool {
    let deadline = Instant::now() + grace;
    let mut readiness = crate::app::Readiness::new(successes);
    let mut next_probe = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_probe {
            let ok = run_healthcheck_command(healthcheck, opts, pid);
            if readiness.observe(ok) {
                return true;
            }
            // Space confirmation probes only after a success; keep probing promptly until the
            // release first answers healthy.
            if ok {
                next_probe = Instant::now() + interval;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, digest: &str) -> updated::bundle::ReleaseId {
        updated::bundle::ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    #[test]
    fn built_in_provider_is_supervisor_versioned_and_accepts_the_full_phase_protocol() {
        assert_eq!(DefaultProvider::VERSION, SELF_VERSION);
        let candidate = release("2.0.0", "two");
        let predecessor = release("1.0.0", "one");
        let provider = BuiltInPhases;
        for phase in [
            LifecyclePhase::Preflight,
            LifecyclePhase::Prepare,
            LifecyclePhase::Drain,
            LifecyclePhase::Stop,
            LifecyclePhase::Activate,
            LifecyclePhase::Start,
            LifecyclePhase::Verify,
            LifecyclePhase::Finalize,
            LifecyclePhase::Rollback,
        ] {
            provider
                .invoke(LifecycleInvocation {
                    phase,
                    reason: LifecycleReason::Update,
                    id: "attempt",
                    pid: Some(42),
                    candidate: &candidate,
                    predecessor: &predecessor,
                })
                .unwrap();
        }
    }

    struct MemoryStore {
        installed: Installed,
        journal: Option<Transaction>,
        active: updated::bundle::ReleaseId,
        rejected: Vec<String>,
    }

    impl MemoryStore {
        fn new(previous: updated::bundle::ReleaseId) -> Self {
            Self {
                installed: Installed::Present(Box::new(InstalledState::confirmed(
                    test_lineage(),
                    previous.clone(),
                    "previous-archive".into(),
                ))),
                journal: None,
                active: previous,
                rejected: Vec::new(),
            }
        }
    }

    impl Store for MemoryStore {
        fn installed(&self) -> Installed {
            match &self.installed {
                Installed::Present(state) => Installed::Present(state.clone()),
                Installed::Missing => Installed::Missing,
                Installed::Invalid => Installed::Invalid,
            }
        }
        fn journal(&self) -> io::Result<Option<Transaction>> {
            Ok(self.journal.clone())
        }
        fn install_journal(
            &self,
        ) -> io::Result<Option<updated::install::InstallTransaction>> {
            Ok(None)
        }
        fn active_release(&self) -> io::Result<Option<updated::bundle::ReleaseId>> {
            Ok(Some(self.active.clone()))
        }
        fn is_rejected(&self, _: &updated::state::RepositoryLineage, _: &str) -> bool {
            false
        }
        fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
            self.installed = Installed::Present(Box::new(state.clone()));
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
        fn write_install_journal(
            &mut self,
            _: &updated::install::InstallTransaction,
        ) -> io::Result<()> {
            Ok(())
        }
        fn clear_install_journal(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn reject(
            &mut self,
            _: &updated::state::RepositoryLineage,
            digest: &str,
        ) -> io::Result<()> {
            self.rejected.push(digest.into());
            Ok(())
        }
        fn clear_rejection(
            &mut self,
            _: &updated::state::RepositoryLineage,
            _: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn activate(&mut self, release: &updated::bundle::ReleaseId) -> io::Result<()> {
            self.active = release.clone();
            Ok(())
        }
    }

    fn test_lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
    }

    #[derive(Default)]
    struct FakeTower {
        phases: Vec<&'static str>,
        fail_drain: bool,
        fail_stop: bool,
        fail_finalize: bool,
        fail_rollback: bool,
        fail_first_start_phase: bool,
        start_phase_calls: usize,
        fail_first_verify_phase: bool,
        verify_phase_calls: usize,
        fail_first_activation: bool,
        fail_process_stop: bool,
        activations: usize,
    }

    impl DeploymentProvider for FakeTower {
        fn drain_hold(&self) -> DrainHold {
            DrainHold::None
        }
        fn traffic_ready(&mut self, _ready: bool) -> io::Result<()> {
            Ok(())
        }

        fn lifecycle(
            &mut self,
            phase: LifecyclePhase,
            _: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.phases.push(phase.name());
            if matches!(phase, LifecyclePhase::Start) {
                self.start_phase_calls += 1;
            }
            if matches!(phase, LifecyclePhase::Verify) {
                self.verify_phase_calls += 1;
            }
            if (matches!(phase, LifecyclePhase::Drain) && self.fail_drain)
                || (matches!(phase, LifecyclePhase::Stop) && self.fail_stop)
                || (matches!(phase, LifecyclePhase::Finalize) && self.fail_finalize)
                || (matches!(phase, LifecyclePhase::Rollback) && self.fail_rollback)
                || (matches!(phase, LifecyclePhase::Start)
                    && self.fail_first_start_phase
                    && self.start_phase_calls == 1)
                || (matches!(phase, LifecyclePhase::Verify)
                    && self.fail_first_verify_phase
                    && self.verify_phase_calls == 1)
            {
                return Err(io::Error::other("injected lifecycle failure"));
            }
            Ok(())
        }
        fn stop(&mut self) -> io::Result<()> {
            if self.fail_process_stop {
                Err(io::Error::other("injected process stop failure"))
            } else {
                Ok(())
            }
        }
        fn activate(
            &mut self,
            _: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.activations += 1;
            if self.fail_first_activation && self.activations == 1 {
                return Err(io::Error::other("injected activation failure"));
            }
            Ok(())
        }
        fn start(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn requires_version_proof(&self) -> bool {
            false
        }
    }

    impl Health for FakeTower {
        async fn became_healthy(&self, _: Option<&str>) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_partial_drain_is_rolled_back_before_its_journal_is_cleared() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_drain: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Deferred));
        assert_eq!(
            tower.phases,
            ["preflight", "prepare", "pre-drain", "drain", "rollback"]
        );
        assert_eq!(tower.activations, 0);
        assert!(store.journal.is_none());
    }

    #[tokio::test]
    async fn a_failed_drain_rollback_preserves_recovery_evidence() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_drain: true,
            fail_rollback: true,
            ..Default::default()
        };

        assert!(apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        .is_err());
        assert!(store.journal.is_some());
    }

    #[tokio::test]
    async fn failed_finalization_rejects_and_defers_rollback_to_boot_recovery() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut tower = FakeTower {
            fail_finalize: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        .unwrap();

        // A post-activation failure rejects the candidate and leaves a durable rollback journal.
        // The restore itself is performed by the one rollback path — boot recovery — after this
        // disposable supervisor terminates and the guardian relaunches it. No in-process rollback
        // phases run here, and the candidate stays activated until recovery reverts it.
        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(
            tower.phases,
            [
                "preflight", "prepare", "pre-drain", "drain", "stop", "start", "verify", "finalize",
            ]
        );
        assert_eq!(tower.activations, 1, "candidate started; no restore in-process");
        assert_eq!(store.active, candidate);
        assert_eq!(store.rejected, vec!["archive-two"]);
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "the rollback journal is left for boot recovery, carrying the rejection decision"
        );
    }

    #[tokio::test]
    async fn failed_stop_phase_rejects_before_the_guardian_or_active_pointer_is_touched() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut provider = FakeTower {
            fail_stop: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut provider,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::RejectedBeforeActivation));
        assert_eq!(store.active, previous);
        assert_eq!(store.rejected, vec!["archive-two"]);
        assert_eq!(provider.activations, 0);
        assert_eq!(
            provider.phases,
            ["preflight", "prepare", "pre-drain", "drain", "stop", "rollback"]
        );
    }

    #[tokio::test]
    async fn failed_process_stop_preserves_recovery_evidence_and_never_activates() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut provider = FakeTower {
            fail_process_stop: true,
            ..Default::default()
        };

        let error = match apply_update(
            &mut provider,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("an unconfirmed process stop must abort activation"),
        };

        assert!(error.to_string().contains("process stop failure"));
        assert_eq!(store.active, previous);
        assert_eq!(provider.activations, 0);
        assert!(
            store.journal.is_some(),
            "boot recovery needs the stop intent"
        );
    }

    #[tokio::test]
    async fn failed_start_or_verify_phase_rejects_and_defers_rollback_to_boot_recovery() {
        for failure in [LifecyclePhase::Start, LifecyclePhase::Verify] {
            let previous = release("1.0.0", "one");
            let candidate = release("2.0.0", "two");
            let mut store = MemoryStore::new(previous.clone());
            let mut provider = FakeTower {
                fail_first_start_phase: matches!(failure, LifecyclePhase::Start),
                fail_first_verify_phase: matches!(failure, LifecyclePhase::Verify),
                ..Default::default()
            };

            let outcome = apply_update(
                &mut provider,
                &mut store,
                &candidate,
                "archive-two",
                test_lineage(),
                None,
                None,
            )
            .await
            .unwrap();

            // Post-activation failure: reject the candidate and leave the rollback journal for boot
            // recovery. The candidate stays activated (recovery restores the predecessor), and no
            // in-process rollback phase runs.
            assert!(matches!(outcome, Outcome::RollbackPending));
            assert_eq!(store.active, candidate);
            assert_eq!(store.rejected, ["archive-two"]);
            assert!(!provider.phases.contains(&"rollback"));
            assert!(store.journal.is_some(), "boot recovery needs the rollback journal");
        }
    }

    #[tokio::test]
    async fn a_failed_activation_records_the_rejection_before_deferring_to_recovery() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_first_activation: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            None,
            None,
        )
        .await
        .unwrap();

        // The candidate activated then failed: it is rejected and the rollback journal is durable
        // before we hand off to boot recovery. There is no in-process rollback to fail.
        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(store.rejected, ["archive-two"]);
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "rollback evidence must retain the rejection decision"
        );
    }

    #[test]
    fn chaos_catalog_is_unique_and_covers_every_supervised_durable_phase() {
        use std::collections::HashSet;

        let catalog: Vec<&str> = BOUNDARIES
            .iter()
            .chain(ROLLBACK_BOUNDARIES)
            .chain(ABORT_BOUNDARIES)
            .copied()
            .collect();
        assert_eq!(catalog.len(), catalog.iter().collect::<HashSet<_>>().len());
        for phase in [
            TransactionPhase::PreflightStarted,
            TransactionPhase::PreflightCompleted,
            TransactionPhase::PrepareStarted,
            TransactionPhase::Prepared,
            TransactionPhase::DrainStarted,
            TransactionPhase::Drained,
            TransactionPhase::StopStarted,
            TransactionPhase::Stopped,
            TransactionPhase::ActivateStarted,
            TransactionPhase::CandidateActivated,
            TransactionPhase::StartStarted,
            TransactionPhase::CandidateStarted,
            TransactionPhase::HealthStarted,
            TransactionPhase::CandidateHealthy,
            TransactionPhase::FinalizeStarted,
            TransactionPhase::Finalized,
            TransactionPhase::CommitStarted,
            TransactionPhase::Committed,
            TransactionPhase::RollbackStarted,
            TransactionPhase::RollbackStopStarted,
            TransactionPhase::RollbackStopped,
            TransactionPhase::RollbackActivateStarted,
            TransactionPhase::PredecessorActivated,
            TransactionPhase::RollbackStartStarted,
            TransactionPhase::PredecessorStarted,
            TransactionPhase::RollbackHealthStarted,
            TransactionPhase::PredecessorHealthy,
            TransactionPhase::RollbackFinalizeStarted,
            TransactionPhase::RolledBack,
            TransactionPhase::Aborted,
        ] {
            assert!(catalog.contains(&boundary::durable_phase(phase)));
        }
    }
}
