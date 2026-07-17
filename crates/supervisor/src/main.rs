//! Update policy, transactions, health checks, and rollback for an application owned
//! by the permanent bootstrap guardian. The supervisor is itself replaceable.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use updated::config::{with_suffix, Activation, Application, Paths, Repository, Timeouts};
use updated::{apply, env, health};
mod app;
mod boot;
mod domain;
mod guardian;
mod options;
mod schedule;
mod selection;
mod self_update;
mod store;
#[cfg(test)]
mod tests;
mod update;

use app::*;
use boot::plan_boot;
use domain::*;
use guardian::Guardian;
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
    repository: Repository,
    application: Application,
    timeouts: Timeouts,
    /// Canonical bundle installation layout.
    paths: Paths,
    supervisor_update: SupervisorUpdate,
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

    fn application_upgraded(&mut self, check_interval: Duration) {
        self.next_app_check = Instant::now() + jitter(check_interval, 20);
    }
}

fn main() {
    // The chaos-feature build can enumerate its own transaction boundaries, so the e2e
    // drives exactly the crossings the supervisor defines instead of a hand-copied list.
    #[cfg(feature = "chaos")]
    if std::env::args().any(|a| a == "--list-chaos-boundaries") {
        for b in update::BOUNDARIES {
            println!("{b}");
        }
        return;
    }

    // reqwest is built without a default TLS provider so the TUF client and
    // health probe share the workspace's single aws-lc-rs implementation.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("supervisor: {e}\n");
            usage();
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = runtime.block_on(run(opts)) {
        eprintln!("supervisor: fatal: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!("usage: supervisor --config <path.toml>");
    eprintln!("all configuration lives in the TOML file; see updated::config.");
}

async fn run(opts: Options) -> Result<(), Box<dyn std::error::Error>> {
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

    let guardian = Guardian::connect().map_err(|e| format!("connecting to the guardian: {e}"))?;
    let guardian_state = guardian::state_dir();

    let mut store = FileStore::open(opts.paths.clone(), opts.timeouts.retry_after)?;

    // Gather the whole world into a Situation and let the pure boot planner decide
    // everything: recovery, drift enforcement, crash rejection, pending confirm/revert,
    // and whether to adopt the running application or launch a fresh one.
    let mut guardian = guardian;
    let situation = gather_situation(&opts, &store, guardian_state.as_deref())?;
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

    // Perform the plan's durable reconciliation (binary, rejections, commit), yielding the
    // still-unconfirmed update (if any) for the loop to confirm once its window passes.
    let mut pending = execute_boot_plan(&plan, &opts, &mut store, &mut guardian, &mut self_update)?;
    if pending.is_some() {
        if let Some(v) = current.as_deref() {
            log(&format!(
                "update {v} is unconfirmed; a crash within its window reverts it"
            ));
        }
    }

    let mut repo: Option<TrustedRepository> = None;

    log(&format!(
        "supervisor {SELF_VERSION} supervising {:?} (product {} channel {}, installed {}, updates {}, restart {}, check every {}s)",
        opts.paths.install_root,
        opts.application.product,
        opts.application.channel,
        current.as_deref().unwrap_or("none"),
        if updates_enabled { "enabled" } else { "DISABLED" },
        opts.application.activation.name(),
        opts.timeouts.check_interval.as_secs()
    ));

    let mut app = match plan.acquire {
        Acquire::Adopt(pid) => adopt(guardian, &opts, pid),
        Acquire::Launch => start(guardian, &opts)?,
    };

    // Gate readiness: the application must be healthy before we trust this boot. A crash
    // would have torn the tower down instead, so an unhealthy result here means the
    // process is alive but wedged — fail closed. For a candidate supervisor, failing this
    // exits before signalling ready, so the guardian rolls the candidate back.
    if !became_healthy(
        &app,
        opts.timeouts.health_grace,
        opts.application.health_url.as_deref(),
        None,
        opts.timeouts.health_successes,
        opts.timeouts.health_interval,
    )
    .await?
    {
        return Err("the managed application failed its initial health check".into());
    }

    // Prove readiness to the guardian. For an ordinary launch this is a no-op; for a
    // candidate supervisor it is what commits the handoff (else the guardian rolls back).
    if let Err(e) = app.signal_ready() {
        warn(&format!("could not signal readiness to the guardian: {e}"));
    }

    let mut loop_state = LoopState::new(opts.timeouts.check_interval);
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
        let wait = app_wait.min(self_update.due_in(now));
        let wait = wait.max(Duration::from_millis(100));

        if sleep_interruptible(wait, &shutdown).await {
            log("shutdown requested; exiting (the guardian stops the application)");
            return Ok(());
        }

        let now = Instant::now();
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

        // One refresh serves both the application and self checks this cycle.
        // Either way we keep running the current version — never fall back to an
        // unverified update — but a trust failure is louder than a transport blip.
        let refresh = match repo.as_mut() {
            Some(repo) => repo.refresh().await,
            None => match TrustedRepository::load(&opts.repository, &opts.paths.datastore).await {
                Ok(loaded) => {
                    repo = Some(loaded);
                    Ok(())
                }
                Err(e) => Err(e),
            },
        };
        if let Err(e) = refresh {
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
        loop_state.refresh_failures = 0;
        let repo = repo
            .as_ref()
            .expect("a successful repository refresh installs a repository");

        // Self-update first: on an accepted handoff this process exits.
        if self_due {
            self_update
                .check(&opts.supervisor_update, repo, &mut app.guardian)
                .await;
        }

        if app_due {
            loop_state.next_app_check = Instant::now() + jitter(opts.timeouts.check_interval, 20);
            match check_application(&opts, repo, &mut store, &mut app, &current).await {
                AppOutcome::Upgraded { version } => {
                    loop_state.application_upgraded(opts.timeouts.check_interval);
                    current = Some(version);
                    // The commit recorded the update as unconfirmed; pick it up so its
                    // window is watched and a crash is caught on the next boot.
                    pending = installed_pending(&store);
                }
                AppOutcome::Unchanged => {}
                AppOutcome::Fatal(message) => {
                    return Err(
                        format!("update transaction requires boot recovery: {message}").into(),
                    );
                }
            }
        }
    }
}

// ============================== boot: gather + execute ==============================

/// Read the whole world the boot planner needs — durable state via the [`Store`] and the
/// guardian's recovery markers — into one [`Situation`]. The shell's single point of input
/// gathering; the marker reads also consume the markers.
fn gather_situation(
    opts: &Options,
    store: &dyn Store,
    guardian_state: Option<&Path>,
) -> io::Result<Situation> {
    let active = store.active_release()?;
    let active_verified = active
        .as_ref()
        .is_some_and(|release| store.verify_release(release).is_ok());
    Ok(Situation {
        installed: store.installed(),
        active,
        active_verified,
        journal: store.journal()?,
        app_crashed: match guardian_state {
            Some(state) => guardian::take_crash_marker(state)?,
            None => false,
        },
        app_running: guardian::adopted_app_pid(),
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
) -> io::Result<Option<Pending>> {
    if plan.quiesce {
        warn("stopping the uncommitted candidate before reconciling its release");
        let _ = guardian.stop();
        let _ = std::fs::remove_file(&opts.paths.app_token);
    }
    apply_store_plan(plan, store)?;
    if let Some(path) = &plan.reject_supervisor {
        self_update.reject_candidate(path);
    }
    Ok(installed_pending(store))
}

/// Apply the durable half of a boot [`Plan`] to the [`Store`].
fn apply_store_plan(plan: &Plan, store: &mut dyn Store) -> io::Result<()> {
    // Commit the intended state before activation; immutable predecessor releases remain
    // available if a crash interrupts pointer reconciliation.
    if let Some(state) = &plan.commit {
        store.commit_installed(state)?;
    }
    match &plan.release {
        ReleaseFix::None => {}
        ReleaseFix::Activate(release) => store.activate(release)?,
    }
    if plan.clear_journal {
        store.clear_journal()?;
    }
    for hash in &plan.reject_app {
        store.reject(hash)?;
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
