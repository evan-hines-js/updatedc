//! The guardian loop.
//!
//! The guardian owns the application and runs a disposable supervisor over an inherited
//! control channel. It is transparent to the init system: it forwards a stop signal
//! *down* to the application, and rolls the application's exit code *up* — when the app
//! exits on its own, the guardian records the crash, tears the tower down, and exits
//! with the app's code, and the init system restarts everything fresh. It never keeps
//! the application alive itself; a crash-looping update is caught on the next start by
//! the supervisor reading the recorded crash, not by any supervision loop here.
//!
//! Everything runs on ONE thread. `poll` watches the control channel while the loop
//! also checks the application process and the shutdown flag; there is no background
//! thread.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use control::{Request, Response};

use crate::log::{error, info, warn};
use crate::probe::Machine as ProbeMachine;
use crate::record;
use crate::service::Service;
use crate::supervisor::{Link, Supervisor};

/// How often the serve loop wakes to re-check the application, the supervisor, and shutdown.
const SERVE_POLL_MS: i32 = 100;
/// The guardian's configuration, all from the command line — it parses no config file
/// (that is the supervisor's job; the path is passed through opaquely).
pub struct Config {
    pub state_dir: PathBuf,
    /// Operator config path, passed verbatim to every supervisor launch.
    pub supervisor_config: PathBuf,
    /// Seed for `desired-supervisor` on first boot, if not already recorded.
    pub initial_supervisor: Option<PathBuf>,
    pub ready_timeout: Duration,
    /// How long a replacement must remain alive after proving ready before its
    /// pointer is committed. The predecessor remains authoritative throughout.
    pub confirm_timeout: Duration,
    /// Grace before hard-killing an application or supervisor during shutdown.
    pub stop_grace: Duration,
    pub probe_address: Option<SocketAddr>,
}

/// Exponential backoff for relaunching a failed supervisor.
///
/// A supervisor that runs a healthy stretch before exiting resets it (a transient crash
/// relaunches promptly). One that keeps exiting immediately — a bricked build that cannot
/// even start, or that fails closed and cannot roll back — backs off toward the cap and
/// loops there forever, waiting for its binary to be fixed. The guardian NEVER gives up
/// and NEVER takes the application down: the app keeps running the entire time.
///
/// The reset is rate-limited, and that is what makes the relaunch loop bounded for the case a
/// duration test alone cannot see: a supervisor that fails *late*. Boot reconciliation can spend
/// well past [`SETTLED`](Self::SETTLED) on an operator lifecycle hook whose timeout the operator
/// chooses, and then exit for relaunch — so "it ran a while" is true on every cycle of a loop
/// that is replaying that hook forever. Counting relaunches per [`WINDOW`](Self::WINDOW) closes
/// it: past [`BURST`](Self::BURST) relaunches in one window nothing resets the backoff, so the
/// delay climbs to the cap however long each attempt takes, and the loop's cost falls to one
/// replay per five minutes.
struct Backoff {
    consecutive: u32,
    base: Duration,
    /// Start of the rate-limit window the relaunches in `in_window` were counted against.
    window_start: Instant,
    relaunches_in_window: u32,
}

impl Backoff {
    const BASE: Duration = Duration::from_secs(2);
    const CAP: Duration = Duration::from_secs(5 * 60);
    /// A supervisor that ran at least this long before exiting was not a start-loop.
    const SETTLED: Duration = Duration::from_secs(30);
    /// The span over which relaunches are counted for the reset rate limit.
    const WINDOW: Duration = Duration::from_secs(60 * 60);
    /// How many relaunches within one [`WINDOW`](Self::WINDOW) still count as occasional
    /// transient crashes. Beyond this the backoff stops resetting, whatever the run durations
    /// were, and escalates to the cap.
    const BURST: u32 = 10;

    fn new() -> Self {
        Backoff {
            consecutive: 0,
            base: Self::base(),
            window_start: Instant::now(),
            relaunches_in_window: 0,
        }
    }

    /// A backoff with an explicit base, for tests that need to advance it without a real
    /// wall-clock sleep (a zero base yields a zero delay).
    #[cfg(test)]
    fn with_base(base: Duration) -> Self {
        Backoff {
            base,
            ..Backoff::new()
        }
    }

    /// The crash-loop base delay. Tunable via `UPDATED_GUARDIAN_BACKOFF_BASE_MS` so a test can
    /// widen the backoff window enough that a shutdown deterministically lands inside the sleep
    /// (never in the brief serve window) — no wall-clock margin to flake. Defaults to [`BASE`].
    fn base() -> Duration {
        std::env::var("UPDATED_GUARDIAN_BACKOFF_BASE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Self::BASE)
    }

    /// The delay before the next relaunch, given how long the last supervisor ran. A run that
    /// lasted longer than [`SETTLED`](Self::SETTLED) resets the backoff to the base — unless this
    /// is already the [`BURST`](Self::BURST)+1st relaunch of the current
    /// [`WINDOW`](Self::WINDOW), in which case nothing resets it and the delay keeps climbing to
    /// the cap. That is the guardian's whole bound on relaunch rate; nothing else throttles a
    /// supervisor that exits to be relaunched.
    fn next(&mut self, ran_for: Duration) -> Duration {
        self.next_at(ran_for, Instant::now())
    }

    /// [`next`](Self::next) against an explicit clock, so the window can be crossed in a test
    /// without an hour of wall clock.
    fn next_at(&mut self, ran_for: Duration, now: Instant) -> Duration {
        if now.duration_since(self.window_start) >= Self::WINDOW {
            self.window_start = now;
            self.relaunches_in_window = 0;
        }
        self.relaunches_in_window = self.relaunches_in_window.saturating_add(1);
        if ran_for >= Self::SETTLED && self.relaunches_in_window <= Self::BURST {
            self.consecutive = 0;
        }
        let delay =
            foundation::time::exponential_backoff(self.base, self.consecutive, 8, Self::CAP);
        self.consecutive = self.consecutive.saturating_add(1);
        delay
    }
}

/// What to do after one supervisor lifetime ends.
enum Cycle {
    /// Relaunch the committed supervisor.
    Continue,
    /// Relaunch it, but pause first (crash-loop guard).
    Backoff,
    /// A stop signal arrived; stop the application and exit.
    Stop,
    /// The supervisor staged a replacement and exited; activate it under a readiness gate.
    Activate(PathBuf),
    /// The service exited on its own — roll its exact exit code up to the init system.
    ServiceExited(i32),
}

/// Run the guardian. Returns the process exit code: `0` for a clean stop, or the
/// service's exact exit code when it exits spontaneously (including zero).
pub fn run(cfg: &Config) -> Result<i32, String> {
    crate::sys::ignore_sigpipe();
    crate::sys::install_shutdown_handler();
    std::fs::create_dir_all(&cfg.state_dir)
        .map_err(|e| format!("creating state dir {}: {e}", cfg.state_dir.display()))?;
    // Reap any half-written record temp orphaned by a prior crash between write and rename,
    // before we start dropping fresh ones. Best-effort hygiene, never a correctness gate.
    let swept = foundation::durable::sweep_stale_temps(&cfg.state_dir, ".guardian-");
    if swept > 0 {
        info(&format!("swept {swept} stale state temp file(s)"));
    }
    seed_desired_supervisor(cfg)?;
    let probes = ProbeMachine::new();
    if let Some(address) = cfg.probe_address {
        crate::probe::serve(address, probes.clone())?;
        info(&format!("guardian probes listening on http://{address}"));
    }

    let mut service = Service::new(probes.clone());
    let mut next: Option<PathBuf> = None; // Some(path) means "activate this candidate"
    let mut backoff = Backoff::new();
    while !crate::sys::shutdown_requested() {
        let launched = Instant::now();
        // A failed supervisor cycle must not take the guardian down with it. By this point the
        // guardian may own a running, healthy application, and its own exit stops that application
        // — so a transient durable-state failure (ENOSPC or EIO recording a rejection, an
        // unwritable state dir) would turn one bad write into a service outage. Log it, back off,
        // and try the cycle again; the application keeps serving throughout. Startup failures that
        // genuinely cannot be recovered from happen before this loop, while nothing is running.
        let cycle = match run_supervisor(cfg, &mut service, next.take()) {
            Ok(cycle) => cycle,
            Err(error) => {
                warn(&format!(
                    "supervisor cycle failed ({error}); the application keeps running and the \
                     cycle is retried"
                ));
                if backoff_pause(&mut backoff, launched.elapsed(), true) {
                    break;
                }
                continue;
            }
        };
        match cycle {
            Cycle::Stop => break,
            Cycle::Continue => {
                // A candidate was rejected (bad launch, missed readiness, exited before
                // confirmation) or a commit was reverted, and we are about to relaunch the
                // committed supervisor. Advance the SAME backoff here so a candidate that
                // passes `send_hello` but fast-crashes before `Ready` cannot drive an
                // unthrottled relaunch loop: the guardian is the backstop and must
                // rate-limit on its own, independent of any supervisor-side policy. Quiet
                // (no per-cycle warning) because this is the normal rejection path.
                if backoff_pause(&mut backoff, launched.elapsed(), false) {
                    break;
                }
            }
            Cycle::Backoff => {
                if backoff_pause(&mut backoff, launched.elapsed(), true) {
                    break;
                }
            }
            Cycle::Activate(path) => next = Some(path),
            Cycle::ServiceExited(code) => return roll_up_service_exit(&cfg.state_dir, code),
        }
    }

    // Transparent clean stop: forward it down to the application.
    info("stop requested; stopping the application and exiting");
    service.stop(cfg.stop_grace);
    Ok(0)
}

/// Apply the perpetual-service exit policy to a neutral child-process outcome. Keeping
/// this policy at the guardian boundary makes the process wrapper reusable without
/// weakening the service contract: every spontaneous exit is durable and unhealthy,
/// and its exact code—including zero—is returned to the outer lifecycle owner.
fn roll_up_service_exit(state_dir: &Path, code: i32) -> Result<i32, String> {
    record::mark_service_exited(state_dir, code)
        .map_err(|error| format!("recording service exit before restart: {error}"))?;
    warn(&format!(
        "application exited (code {code}); rolling it up and letting the init system restart"
    ));
    Ok(code)
}

/// Launch one supervisor (the committed one, or `candidate` for a gated activation) and
/// serve it until it exits, is replaced, the service exits, or a stop arrives.
fn run_supervisor(
    cfg: &Config,
    service: &mut Service,
    candidate: Option<PathBuf>,
) -> Result<Cycle, String> {
    let binary = match &candidate {
        Some(path) => path.clone(),
        None => record::desired_supervisor(&cfg.state_dir)
            .map_err(|e| format!("reading committed supervisor pointer: {e}"))?
            .ok_or_else(|| {
                "no committed supervisor recorded and none supplied (--supervisor)".to_string()
            })?,
    };
    validate_supervisor_path(cfg, &binary, candidate.is_some())?;

    // A service exit that landed while the guardian was between supervisors (the backoff
    // sleep, or a handoff) is only visible here — `poll_exit` runs solely inside serve.
    // Surface it before adopting/launching, or the exit would be silently
    // discarded (the next `app.launch` reaps the dead proc) and the bad update relaunched
    // instead of rolled up and reverted.
    if let Some(code) = service.poll_exit() {
        return Ok(Cycle::ServiceExited(code));
    }

    // If an application is already running (a supervisor crash-relaunch, or a candidate
    // activation over the previous supervisor's app), hand its PID to the new supervisor
    // so it adopts rather than launching a duplicate.
    let app_pid = if service.is_running() {
        service.pid()
    } else {
        None
    };

    let mut sup = match Supervisor::launch(
        &binary,
        &cfg.supervisor_config,
        &cfg.state_dir,
        app_pid,
        cfg.stop_grace,
    ) {
        Ok(sup) => sup,
        Err(e) => {
            if let Some(path) = &candidate {
                warn(&format!(
                    "candidate supervisor {} could not be launched ({e}); rejecting",
                    path.display()
                ));
                record::mark_rejected_supervisor(&cfg.state_dir, path).map_err(|marker| {
                    format!("candidate {} failed to launch ({e}) and recording its rejection failed: {marker}", path.display())
                })?;
                return Ok(Cycle::Continue);
            }
            error(&format!(
                "cannot launch committed supervisor {}: {e}",
                binary.display()
            ));
            return Ok(Cycle::Backoff);
        }
    };
    info(&format!(
        "launched supervisor {} (pid {}){}",
        binary.display(),
        sup.pid(),
        if candidate.is_some() {
            " under a readiness gate"
        } else {
            ""
        }
    ));
    serve_service(cfg, &mut sup, service, candidate)
}

fn serve_service<L: Link>(
    cfg: &Config,
    sup: &mut L,
    service: &mut Service,
    candidate: Option<PathBuf>,
) -> Result<Cycle, String> {
    // When activating, we must see a matching readiness ack before the deadline.
    let mut activation = ActivationState {
        committed: candidate.is_none(),
        candidate,
        ready_since: None,
        pending_replace: None,
    };
    let deadline = Instant::now() + cfg.ready_timeout;

    if sup.send_hello().is_err() {
        sup.stop();
        return conclude(cfg, &mut activation, "failed the control handshake");
    }

    loop {
        if crate::sys::shutdown_requested() {
            sup.stop();
            return Ok(Cycle::Stop);
        }
        if !activation.committed && activation.ready_since.is_none() && Instant::now() >= deadline {
            sup.stop();
            return conclude(cfg, &mut activation, "did not signal ready in time");
        }

        if sup.poll_readable(SERVE_POLL_MS) {
            match sup.read_request() {
                Ok(req) => {
                    if dispatch(cfg, sup, service, req, &mut activation).is_err() {
                        // A response write failed — a partial/timed-out frame may already be on the
                        // wire. Never keep serving this channel: the very next response would land
                        // after a half-written one and desync the supervisor's frame reader (and on
                        // Windows an abandoned write thread could interleave bytes). Stop the
                        // supervisor and relaunch it on a fresh channel rather than trusting the
                        // peer to eventually exit on its own.
                        sup.stop();
                        return conclude(cfg, &mut activation, "could not be written to");
                    }
                }
                // Forward compatibility, not a fault: a newer supervisor may send a tag this
                // guardian has never heard of. Answer `Unsupported` and keep serving.
                Err(control::Error::UnknownTag(_)) => {
                    let _ = sup.send_response(&Response::Unsupported);
                }
                // Any other read failure ends this supervisor's usefulness, so it ends its
                // lifetime — through the same `conclude` every other ending goes through.
                //
                // The common cause is the ordinary one: the supervisor EXITED, and on Unix its
                // closed socketpair reports readable-with-hangup forever, so the read fails on
                // the very poll that would otherwise observe the exit. That is not a channel
                // fault and must not be logged or reported as one.
                //
                // A supervisor still RUNNING without a usable channel is the real fault, and it
                // must not be left running: `poll_readable` would return immediately on every
                // iteration and pin a core at 100% for as long as it lives.
                Err(error) => {
                    let reason = if sup.exited() {
                        "exited"
                    } else {
                        warn(&format!(
                            "the supervisor's control channel is unusable ({error}); stopping it"
                        ));
                        sup.stop();
                        "lost its control channel"
                    };
                    return conclude(cfg, &mut activation, reason);
                }
            }
        }

        // A spontaneous service exit takes priority: roll its exact code up and tear down.
        if let Some(code) = service.poll_exit() {
            sup.stop();
            return Ok(Cycle::ServiceExited(code));
        }

        if sup.exited() {
            return conclude(cfg, &mut activation, "exited");
        }

        // Commit only after proving the candidate is still alive in this iteration.
        // Otherwise an exit racing the timer boundary could leave a dead desired pointer.
        if !activation.committed
            && activation
                .ready_since
                .is_some_and(|ready| ready.elapsed() >= cfg.confirm_timeout)
        {
            let path = activation
                .candidate
                .as_ref()
                .expect("activation has a candidate");
            if let Err(e) = record::set_desired_supervisor(&cfg.state_dir, path) {
                error(&format!(
                    "committing stable supervisor {} failed: {e}; reverting to its predecessor",
                    path.display()
                ));
                sup.stop();
                return conclude(cfg, &mut activation, "could not be committed");
            }
            info(&format!(
                "candidate {} survived its confirmation window; committed as the supervisor",
                path.display()
            ));
            activation.committed = true;
        }
    }
}

struct ActivationState {
    candidate: Option<PathBuf>,
    committed: bool,
    ready_since: Option<Instant>,
    pending_replace: Option<PathBuf>,
}

/// End one supervisor's lifetime and decide what the guardian does next. `reason` completes the
/// sentence "the supervisor/candidate …" in the log line.
///
/// EVERY way of leaving [`serve_service`] short of a stop signal or a service exit funnels
/// through here — the process exited, its channel died, it never signalled ready, its commit
/// failed — because two obligations must not depend on which of those happened:
///
///  * An uncommitted candidate is ALWAYS recorded rejected. Its bytes live in a
///    content-addressed slot, so a supervisor that is not told the hash failed re-selects it,
///    re-stages it into the same slot, and hands it off again, forever.
///  * A staged replacement is ALWAYS activated. Dropping it means self-update silently never
///    completes: the committed supervisor comes back, re-stages the same candidate, and the
///    same handoff repeats every cycle.
///
/// Rejection is checked first: a candidate that staged a replacement before proving itself is
/// still an unconfirmed candidate, and rolling back to its predecessor is what must happen.
fn conclude(cfg: &Config, activation: &mut ActivationState, reason: &str) -> Result<Cycle, String> {
    if !activation.committed {
        let path = activation
            .candidate
            .as_ref()
            .expect("an uncommitted activation always has a candidate");
        warn(&format!(
            "candidate {} {reason}; rolling back and rejecting it",
            path.display()
        ));
        record::mark_rejected_supervisor(&cfg.state_dir, path).map_err(|e| {
            format!(
                "recording rejection of supervisor {} ({reason}): {e}",
                path.display()
            )
        })?;
        return Ok(Cycle::Continue);
    }
    if let Some(path) = activation.pending_replace.take() {
        info(&format!(
            "supervisor {reason} after staging a replacement; activating {}",
            path.display()
        ));
        return Ok(Cycle::Activate(path));
    }
    // The supervisor is gone but the application is fine — the guardian relaunches the
    // supervisor (with backoff) over the still-running app.
    warn(&format!(
        "supervisor {reason} (the application keeps running)"
    ));
    Ok(Cycle::Backoff)
}

/// Handle one control request, replying on the channel.
fn dispatch<L: Link>(
    cfg: &Config,
    sup: &mut L,
    service: &mut Service,
    req: Request,
    activation: &mut ActivationState,
) -> control::Result<()> {
    let response = match req {
        Request::Launch(spec) => match service.launch(&spec, cfg.stop_grace) {
            Ok(pid) => {
                info(&format!("launched application pid {pid}"));
                Response::Launched { pid }
            }
            Err(e) => {
                warn(&format!("application launch failed: {e}"));
                Response::Error(e.to_string())
            }
        },
        Request::Stop => {
            service.stop(cfg.stop_grace);
            Response::Ok
        }
        Request::ReplaceSupervisor(path) => {
            // The guardian keeps no rejection set: the supervisor is responsible for not
            // re-staging a candidate it already knows failed (it read the marker). The
            // guardian just accepts the handoff and activates it when this supervisor exits.
            let path = PathBuf::from(path);
            match validate_supervisor_path(cfg, &path, true) {
                Ok(()) => {
                    activation.pending_replace = Some(path);
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::Ready(nonce) => {
            if !activation.committed && nonce == sup.nonce() {
                if let Some(path) = activation.candidate.as_deref() {
                    if activation.ready_since.is_none() {
                        info(&format!(
                            "candidate {} proved ready; beginning its confirmation window",
                            path.display()
                        ));
                        activation.ready_since = Some(Instant::now());
                    }
                }
            }
            Response::Ok
        }
        Request::TrafficReady(ready) => {
            // A durable record of each readiness edge. The probe endpoints only reflect
            // the withdrawal transiently (readiness drops, then returns once the candidate
            // is healthy), so this log — emitted once per edge, not once per poll — is the
            // deterministic signal that the guardian drained traffic without ever taking
            // the live tower down.
            if service.traffic_ready(ready) {
                if ready {
                    info("returned the application to traffic; readiness restored");
                } else {
                    info("withdrew the application from traffic; the tower stays live");
                }
            }
            Response::Ok
        }
        Request::ApplicationFailed => {
            service.fail(cfg.stop_grace);
            Response::Ok
        }
    };
    sup.send_response(&response)
}

/// On first boot, record the supplied initial supervisor as the committed one.
fn seed_desired_supervisor(cfg: &Config) -> Result<(), String> {
    if let Some(committed) = record::desired_supervisor(&cfg.state_dir)
        .map_err(|e| format!("reading committed supervisor pointer: {e}"))?
    {
        return validate_supervisor_path(cfg, &committed, false);
    }
    let initial = cfg
        .initial_supervisor
        .as_ref()
        .ok_or("no committed supervisor and no --supervisor to seed one")?;
    // Durably record the seeded path BEFORE the pointer, so a later boot trusts it flag-free (see
    // `validate_supervisor_path`). A crash between the two just re-seeds identically next boot.
    record::set_seeded_supervisor(&cfg.state_dir, initial)
        .map_err(|e| format!("recording the seeded supervisor: {e}"))?;
    validate_supervisor_path(cfg, initial, false)?;
    record::set_desired_supervisor(&cfg.state_dir, initial)
        .map_err(|e| format!("recording the initial supervisor: {e}"))
}

/// Validate that `path` is a safe supervisor binary to launch (a regular non-symlink file
/// inside the content-addressed staging tree, or the durably-seeded initial path).
///
/// This is a TOCTOU check: the file could in principle be swapped between this validation
/// and the subsequent `Supervisor::launch`. The window is acceptable and bounded because
/// the staging tree lives under the guardian's own root-owned `state_dir` — an attacker who
/// could rewrite content-addressed paths there already owns the node — and because the path
/// is content-addressed (`supervisors/<sha256>/…`), so a swap that preserved the hash
/// directory name would have to preserve the bytes. The check exists to reject
/// misconfiguration and stray symlinks, not to defend a hostile-writer race, so re-opening
/// atomically to close the window would buy nothing.
fn validate_supervisor_path(cfg: &Config, path: &Path, candidate: bool) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("inspecting supervisor {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "supervisor {} must be a regular, non-symlink file",
            path.display()
        ));
    }
    if !candidate {
        // Trust a non-staging committed path only if it matches the DURABLE seeded record (written
        // at first boot while `--supervisor` was present) — not the live `--supervisor` flag. This
        // means the flag can be dropped on any later restart without bricking a node that has never
        // self-updated (its committed pointer is still the installer-placed raw path). A node that
        // HAS self-updated has a staging-tree pointer and never reaches here.
        if let Ok(Some(seeded)) = record::seeded_supervisor(&cfg.state_dir) {
            // Both sides must resolve: comparing `.ok()` would make two *failures* compare equal
            // (None == None) and wave the path through without reaching the staging check below.
            if let (Ok(resolved), Ok(seeded)) =
                (std::fs::canonicalize(path), std::fs::canonicalize(&seeded))
            {
                if resolved == seeded {
                    return Ok(());
                }
            }
        }
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("canonicalizing supervisor {}: {e}", path.display()))?;
    let root = std::fs::canonicalize(cfg.state_dir.join("supervisors"))
        .map_err(|e| format!("canonicalizing supervisor staging directory: {e}"))?;
    let relative = canonical.strip_prefix(&root).map_err(|_| {
        format!(
            "supervisor {} is outside the managed staging directory",
            path.display()
        )
    })?;
    let parts: Vec<_> = relative.components().collect();
    let expected_name = foundation::platform::supervisor_binary_name();
    if parts.len() != 2
        || parts[0]
            .as_os_str()
            .to_str()
            .is_none_or(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        || parts[1].as_os_str() != expected_name
    {
        return Err(format!(
            "supervisor {} must be supervisors/<64-hex-sha256>/{expected_name}",
            path.display()
        ));
    }
    Ok(())
}

/// Advance the relaunch backoff and sleep it out before the next supervisor launch.
/// Returns `true` if a stop cut the sleep short (the caller then exits without relaunching).
///
/// Both the crash-loop path (`Cycle::Backoff`) and the candidate-rejection path
/// (`Cycle::Continue`) funnel through here so relaunch is throttled the same way regardless
/// of which one triggered it. `announce` logs the wait for the crash-loop case; the
/// candidate-rejection case stays quiet to avoid a warning on every routine rejection.
fn backoff_pause(backoff: &mut Backoff, ran_for: Duration, announce: bool) -> bool {
    let delay = backoff.next(ran_for);
    if announce {
        warn(&format!(
            "relaunching the supervisor in {}s (the application keeps running)",
            delay.as_secs()
        ));
    }
    if sleep_interruptible(delay) {
        // Emitted ONLY when shutdown cut the backoff sleep short (never when the sleep
        // elapsed and we relaunch), so a test can prove interruption from durable evidence
        // instead of racing a wall clock.
        info("shutdown interrupted the relaunch backoff; exiting without relaunch");
        true
    } else {
        false
    }
}

/// Sleep up to `dur`, returning `true` early if a stop signal arrives.
fn sleep_interruptible(dur: Duration) -> bool {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if crate::sys::shutdown_requested() {
            return true;
        }
        // Poll finely: a stop signal must interrupt a multi-second backoff promptly even
        // when the machine is heavily loaded and this thread is slow to be scheduled.
        std::thread::sleep(Duration::from_millis(25));
    }
    crate::sys::shutdown_requested()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::probe::State as ProbeState;

    const INSTANT: Duration = Duration::from_millis(10); // a supervisor that died at once

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let mut b = Backoff::new();
        // A start-loop: each relaunch backs off further, from the base to the cap.
        assert_eq!(b.next(INSTANT), Duration::from_secs(2));
        assert_eq!(b.next(INSTANT), Duration::from_secs(4));
        assert_eq!(b.next(INSTANT), Duration::from_secs(8));
        assert_eq!(b.next(INSTANT), Duration::from_secs(16));
        // ...and keeps looping at the cap forever (never gives up).
        for _ in 0..20 {
            b.next(INSTANT);
        }
        assert_eq!(b.next(INSTANT), Backoff::CAP);
    }

    #[test]
    fn candidate_rejection_cycles_rate_limit_the_relaunch() {
        // A candidate that passes `send_hello` but fast-crashes before `Ready` returns
        // `Cycle::Continue`. The guardian must throttle the resulting relaunch itself rather
        // than trust supervisor policy, so every rejection cycle advances the shared backoff.
        // A zero base makes the pause a no-op sleep, so the test asserts the advance without
        // a wall-clock delay.
        let mut backoff = Backoff::with_base(Duration::ZERO);
        assert_eq!(backoff.consecutive, 0);
        for expected in 1..=4 {
            // announce = false is exactly the candidate-rejection (Cycle::Continue) path.
            assert!(
                !backoff_pause(&mut backoff, INSTANT, false),
                "no shutdown, so the pause completes and the guardian relaunches"
            );
            assert_eq!(
                backoff.consecutive, expected,
                "each candidate-rejection cycle advances the backoff, throttling the relaunch"
            );
        }
    }

    #[test]
    fn a_supervisor_that_ran_a_while_resets_the_backoff() {
        let mut b = Backoff::new();
        b.next(INSTANT);
        b.next(INSTANT);
        b.next(INSTANT); // backed off a few times
                         // A supervisor that ran past the settle threshold before exiting is a transient
                         // crash, not a start-loop: the next relaunch is prompt again.
        assert_eq!(b.next(Backoff::SETTLED), Duration::from_secs(2));
    }

    #[test]
    fn a_supervisor_that_fails_late_on_every_cycle_still_backs_off() {
        // The path this bound exists for: the supervisor exits for relaunch AFTER a long boot —
        // boot reconciliation replaying an operator lifecycle hook whose timeout the operator
        // chooses can easily outlast SETTLED. "It ran a while" is then true on every cycle, so a
        // duration-only reset would hold the delay at the 2s base forever and the node would
        // replay that hook roughly once per boot, indefinitely. Counting relaunches per window
        // makes the loop bounded regardless of how long each attempt takes.
        let long_boot = Backoff::SETTLED * 2;
        let mut b = Backoff::with_base(Backoff::BASE);
        let start = Instant::now();
        for _ in 0..Backoff::BURST {
            assert_eq!(
                b.next_at(long_boot, start),
                Duration::from_secs(2),
                "an occasional late failure still relaunches promptly"
            );
        }
        // Past the burst allowance the run duration stops earning a reset, so the delay climbs.
        assert_eq!(b.next_at(long_boot, start), Duration::from_secs(4));
        assert_eq!(b.next_at(long_boot, start), Duration::from_secs(8));
        assert_eq!(b.next_at(long_boot, start), Duration::from_secs(16));
        for _ in 0..20 {
            b.next_at(long_boot, start);
        }
        assert_eq!(
            b.next_at(long_boot, start),
            Backoff::CAP,
            "a late-failing relaunch loop reaches the same five-minute cap as a start-loop"
        );

        // A new window starts fresh: a node whose supervisor fails once an hour is not a loop,
        // and must not be left waiting five minutes to recover.
        assert_eq!(
            b.next_at(long_boot, start + Backoff::WINDOW),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn the_backoff_cap_is_five_minutes() {
        // Pin the concrete cap, not just "== Backoff::CAP" (which a mutated CAP satisfies).
        assert_eq!(Backoff::CAP, Duration::from_secs(300));
        let mut b = Backoff::new();
        for _ in 0..30 {
            b.next(INSTANT);
        }
        assert_eq!(
            b.next(INSTANT),
            Duration::from_secs(300),
            "a start-loop caps at 300s"
        );
    }

    // ------------------------ the control state machine (Link + App fakes) ------------------------

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A scripted supervisor control link: poll/read/exit results are queues consumed
    /// front-to-back; sent responses and stop calls are captured for assertions.
    struct FakeLink {
        nonce: control::Nonce,
        hello_ok: bool,
        readable: RefCell<VecDeque<bool>>,
        requests: VecDeque<control::Request>,
        exited: VecDeque<bool>,
        responses: Vec<control::Response>,
        stops: u32,
    }

    impl FakeLink {
        fn new() -> Self {
            FakeLink {
                nonce: [0u8; 16],
                hello_ok: true,
                readable: RefCell::new(VecDeque::new()),
                requests: VecDeque::new(),
                exited: VecDeque::new(),
                responses: Vec::new(),
                stops: 0,
            }
        }
    }

    impl Link for FakeLink {
        fn nonce(&self) -> control::Nonce {
            self.nonce
        }
        fn send_hello(&mut self) -> control::Result<()> {
            if self.hello_ok {
                Ok(())
            } else {
                Err(control::Error::Closed)
            }
        }
        fn poll_readable(&self, _timeout_ms: i32) -> bool {
            self.readable.borrow_mut().pop_front().unwrap_or(false)
        }
        fn read_request(&mut self) -> control::Result<control::Request> {
            self.requests.pop_front().ok_or(control::Error::Closed)
        }
        fn send_response(&mut self, resp: &control::Response) -> control::Result<()> {
            self.responses.push(resp.clone());
            Ok(())
        }
        fn exited(&mut self) -> bool {
            // Script exhaustion is a supervisor exit. This gives every state-machine test
            // a finite fallback: a broken deadline is reported by the assertions instead
            // of hanging the mutation runner forever.
            self.exited.pop_front().unwrap_or(true)
        }
        fn stop(&mut self) {
            self.stops += 1;
        }
    }

    /// A fake application process that starts cleanly and never crashes.
    struct FakeProc;
    impl crate::sys::Process for FakeProc {
        fn pid(&self) -> u32 {
            4242
        }
        fn poll_exit(&mut self) -> Option<i32> {
            None
        }
        fn stop(&mut self, _grace: Duration) {}
    }
    fn fake_spawn(_spec: &control::CommandSpec) -> std::io::Result<Box<dyn crate::sys::Process>> {
        Ok(Box::new(FakeProc))
    }

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("guardian-test-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(state_dir: PathBuf, initial: Option<PathBuf>) -> Config {
        Config {
            state_dir,
            supervisor_config: PathBuf::from("/etc/supervisor.toml"),
            initial_supervisor: initial,
            ready_timeout: Duration::from_secs(30),
            confirm_timeout: Duration::from_secs(30),
            stop_grace: Duration::from_secs(10),
            probe_address: None,
        }
    }

    fn spec() -> control::CommandSpec {
        control::CommandSpec {
            program: OsString::from("/opt/app"),
            args: vec![],
            env: vec![],
            cwd: None,
        }
    }

    fn rejected_marker(c: &Config) -> Option<String> {
        std::fs::read_to_string(c.state_dir.join(control::REJECTED_SUPERVISOR_FILE)).ok()
    }

    fn staged_candidate(c: &Config, byte: u8) -> PathBuf {
        let digest = format!("{byte:02x}").repeat(32);
        let dir = c.state_dir.join("supervisors").join(digest);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(foundation::platform::supervisor_binary_name());
        std::fs::write(&path, b"candidate").unwrap();
        path
    }

    fn activation(candidate: Option<PathBuf>, committed: bool) -> ActivationState {
        ActivationState {
            candidate,
            committed,
            ready_since: None,
            pending_replace: None,
        }
    }

    #[test]
    fn exit_zero_is_rolled_up_unchanged_by_service_policy() {
        let state_dir = temp_dir("exit-zero");

        assert_eq!(roll_up_service_exit(&state_dir, 0).unwrap(), 0);
        assert!(state_dir
            .join(control::SERVICE_EXITED_MARKER_FILE)
            .is_file());
    }

    #[test]
    fn dispatch_launch_starts_the_app_and_replies_launched() {
        let c = cfg(temp_dir("launch"), None);
        let mut sup = FakeLink::new();
        let mut app = Service::with_process(App::with_spawn(fake_spawn));
        let mut state = activation(None, true);
        dispatch(&c, &mut sup, &mut app, Request::Launch(spec()), &mut state).unwrap();
        assert_eq!(sup.responses, vec![Response::Launched { pid: 4242 }]);
    }

    #[test]
    fn dispatch_stop_replies_ok() {
        let c = cfg(temp_dir("stop"), None);
        let mut sup = FakeLink::new();
        let mut app = Service::with_process(App::with_spawn(fake_spawn));
        let mut state = activation(None, true);
        dispatch(&c, &mut sup, &mut app, Request::Stop, &mut state).unwrap();
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn traffic_requests_drive_the_guardian_probe_state_machine() {
        let c = cfg(temp_dir("traffic-state"), None);
        let mut sup = FakeLink::new();
        let probes = ProbeMachine::new();
        let mut app = Service::new(probes.clone());
        let mut state = activation(None, true);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::TrafficReady(true),
            &mut state,
        )
        .unwrap();
        assert_eq!(probes.state(), ProbeState::Serving);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::TrafficReady(false),
            &mut state,
        )
        .unwrap();
        assert_eq!(probes.state(), ProbeState::Unready);
    }

    #[test]
    fn dispatch_replace_stages_the_candidate_and_replies_ok() {
        let c = cfg(temp_dir("replace"), None);
        let mut sup = FakeLink::new();
        let mut app = Service::with_process(App::none());
        let mut state = activation(None, true);
        let candidate = staged_candidate(&c, 0x11);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::ReplaceSupervisor(candidate.as_os_str().to_owned()),
            &mut state,
        )
        .unwrap();
        assert_eq!(state.pending_replace, Some(candidate));
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_replace_rejects_paths_outside_content_addressed_staging() {
        let c = cfg(temp_dir("replace-invalid"), None);
        let outside = c.state_dir.join("arbitrary-supervisor");
        std::fs::write(&outside, b"candidate").unwrap();
        let mut sup = FakeLink::new();
        let mut app = Service::with_process(App::none());
        let mut state = activation(None, true);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::ReplaceSupervisor(outside.into_os_string()),
            &mut state,
        )
        .unwrap();
        assert!(state.pending_replace.is_none());
        assert!(matches!(sup.responses.as_slice(), [Response::Error(_)]));
    }

    #[test]
    fn dispatch_ready_with_the_matching_nonce_begins_confirmation() {
        let c = cfg(temp_dir("ready-ok"), None);
        let cand = PathBuf::from("/state/supervisors/abc/supervisor");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut app = Service::with_process(App::none());
        let mut state = activation(Some(cand), false);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([7u8; 16]),
            &mut state,
        )
        .unwrap();
        assert!(
            !state.committed,
            "readiness alone must not commit the candidate"
        );
        assert!(state.ready_since.is_some(), "the stability window begins");
        assert!(record::desired_supervisor(&c.state_dir).unwrap().is_none());
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_ready_with_a_wrong_nonce_does_not_commit() {
        let c = cfg(temp_dir("ready-wrong"), None);
        let cand = PathBuf::from("/state/supervisors/abc/supervisor");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut app = Service::with_process(App::none());
        let mut state = activation(Some(cand), false);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([9u8; 16]),
            &mut state,
        )
        .unwrap();
        assert!(!state.committed, "a wrong nonce must not commit");
        assert!(state.ready_since.is_none());
        assert!(
            record::desired_supervisor(&c.state_dir).unwrap().is_none(),
            "the desired pointer is untouched"
        );
        assert_eq!(
            sup.responses,
            vec![Response::Ok],
            "the request is still acknowledged"
        );
    }

    #[test]
    fn dispatch_ready_when_already_committed_does_not_re_commit() {
        let c = cfg(temp_dir("ready-committed"), None);
        let cand = PathBuf::from("/state/supervisors/abc/supervisor");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut app = Service::with_process(App::none());
        let mut state = activation(Some(cand), true);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([7u8; 16]),
            &mut state,
        )
        .unwrap();
        assert!(
            record::desired_supervisor(&c.state_dir).unwrap().is_none(),
            "an already-committed serve never re-commits"
        );
    }

    #[test]
    fn an_exited_supervisors_closed_channel_still_activates_its_staged_replacement() {
        // On Unix an exited supervisor leaves its socketpair readable-with-hangup, so the read
        // fails with `Closed` on the very poll that would otherwise observe the exit. Treating
        // that as a channel fault discarded the staged replacement — self-update silently never
        // activated, and the old supervisor came back every time.
        let c = cfg(temp_dir("closed-after-replace"), None);
        let staged = staged_candidate(&c, 0x22);
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true); // ReplaceSupervisor arrives
        sup.readable.borrow_mut().push_back(true); // then the channel reads as closed
        sup.requests
            .push_back(Request::ReplaceSupervisor(staged.clone().into_os_string()));
        sup.exited.push_back(false); // still running when it staged the replacement
        let mut app = Service::with_process(App::none());

        let cycle = serve_service(&c, &mut sup, &mut app, None).unwrap();
        assert!(
            matches!(cycle, Cycle::Activate(path) if path == staged),
            "the staged replacement must still be activated"
        );
    }

    #[test]
    fn an_exited_candidates_closed_channel_still_rejects_it() {
        // Same Unix readable-with-hangup read failure, seen while gating a candidate: the
        // rejection marker is what stops the supervisor re-selecting and re-staging the same
        // content-addressed bytes forever, so it must be written on this path too.
        let c = cfg(temp_dir("closed-candidate"), None);
        let cand = PathBuf::from("/state/supervisors/dead/supervisor");
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true); // readable-with-hangup, nothing to read
        let mut app = Service::with_process(App::none());

        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn a_running_supervisor_that_loses_its_channel_is_stopped() {
        // A live supervisor without a usable channel would spin `poll_readable` at 100% forever.
        // It is stopped and relaunched on a fresh one; the application is untouched.
        let c = cfg(temp_dir("channel-lost"), None);
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true);
        sup.exited.push_back(false); // still running when the read fails
        let mut app = Service::with_process(App::none());

        let cycle = serve_service(&c, &mut sup, &mut app, None).unwrap();
        assert!(matches!(cycle, Cycle::Backoff));
        assert_eq!(sup.stops, 1, "the supervisor is stopped, not left spinning");
        assert!(rejected_marker(&c).is_none(), "nothing to reject");
    }

    #[test]
    fn a_candidate_that_loses_its_channel_while_running_is_rejected() {
        let c = cfg(temp_dir("channel-lost-candidate"), None);
        let cand = PathBuf::from("/state/supervisors/mute/supervisor");
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true);
        sup.exited.push_back(false);
        let mut app = Service::with_process(App::none());

        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(
            rejected_marker(&c).as_deref(),
            cand.to_str(),
            "a candidate that cannot be talked to is rejected, not retried forever"
        );
    }

    #[test]
    fn a_hello_that_fails_rejects_a_candidate_and_only_backs_off_a_committed_supervisor() {
        let c = cfg(temp_dir("hello-candidate"), None);
        let cand = PathBuf::from("/state/supervisors/mismatch/supervisor");
        let mut sup = FakeLink::new();
        sup.hello_ok = false;
        let mut app = Service::with_process(App::none());
        assert!(matches!(
            serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap(),
            Cycle::Continue
        ));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());

        let c = cfg(temp_dir("hello-committed"), None);
        let mut sup = FakeLink::new();
        sup.hello_ok = false;
        assert!(matches!(
            serve_service(&c, &mut sup, &mut app, None).unwrap(),
            Cycle::Backoff
        ));
        assert!(rejected_marker(&c).is_none());
    }

    #[test]
    fn serve_rejects_a_candidate_that_never_signals_ready_before_the_deadline() {
        let mut c = cfg(temp_dir("timeout"), None);
        c.ready_timeout = Duration::ZERO; // the deadline is already past on the first poll.
        let cand = PathBuf::from("/state/supervisors/slow/supervisor");
        let mut sup = FakeLink::new();
        let mut app = Service::with_process(App::none());
        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(
            matches!(cycle, Cycle::Continue),
            "a timed-out candidate rolls back to the committed supervisor"
        );
        assert!(sup.stops >= 1, "the candidate is stopped");
        assert_eq!(
            rejected_marker(&c).as_deref(),
            cand.to_str(),
            "and recorded rejected"
        );
    }

    #[test]
    fn serve_rejects_a_candidate_that_exits_before_signalling_ready() {
        let cand = PathBuf::from("/state/supervisors/dead/supervisor");
        let c = cfg(temp_dir("preexit"), None);
        let mut sup = FakeLink::new();
        sup.exited.push_back(true); // exits before any Ready
        let mut app = Service::with_process(App::none());
        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn serve_rejects_a_candidate_that_exits_during_confirmation() {
        let cand = PathBuf::from("/state/supervisors/good/supervisor");
        let c = cfg(temp_dir("postready"), None);
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false); // still running right after readying...
        sup.exited.push_back(true); // ...then exits
        let mut app = Service::with_process(App::none());
        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(
            matches!(cycle, Cycle::Continue),
            "an unconfirmed supervisor rolls back immediately"
        );
        assert!(
            rejected_marker(&c).as_deref() == cand.to_str(),
            "an unstable candidate is rejected"
        );
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            None,
            "an unstable candidate must never become desired"
        );
    }

    #[test]
    fn serve_commits_only_after_the_confirmation_window() {
        let cand = PathBuf::from("/state/supervisors/stable/supervisor");
        let mut c = cfg(temp_dir("confirmed"), None);
        c.confirm_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false);
        sup.exited.push_back(true);
        let mut app = Service::with_process(App::none());
        let cycle = serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Backoff));
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            Some(cand)
        );
        assert!(rejected_marker(&c).is_none());
    }

    #[test]
    fn exit_at_confirmation_deadline_loses_to_liveness_check() {
        let cand = PathBuf::from("/state/supervisors/racy/supervisor");
        let mut c = cfg(temp_dir("confirmation-race"), None);
        c.confirm_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(true);
        let mut app = Service::with_process(App::none());
        assert!(matches!(
            serve_service(&c, &mut sup, &mut app, Some(cand.clone())).unwrap(),
            Cycle::Continue
        ));
        assert_eq!(record::desired_supervisor(&c.state_dir).unwrap(), None);
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn serve_never_lets_the_deadline_reject_an_ordinary_committed_supervisor() {
        let mut c = cfg(temp_dir("committed"), None);
        c.ready_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.exited.push_back(true); // a plain committed supervisor that crashes
        let mut app = Service::with_process(App::none());
        let cycle = serve_service(&c, &mut sup, &mut app, None).unwrap(); // candidate None ⇒ already committed
        assert!(
            matches!(cycle, Cycle::Backoff),
            "a committed supervisor is never rejected by the readiness deadline"
        );
        assert!(rejected_marker(&c).is_none());
    }

    #[test]
    fn seed_preserves_an_existing_desired_pointer() {
        let state = temp_dir("seed-existing");
        let initial = state.join("initial-supervisor");
        std::fs::write(&initial, b"initial").unwrap();
        let c = cfg(state, Some(initial));
        let existing = staged_candidate(&c, 0x22);
        record::set_desired_supervisor(&c.state_dir, &existing).unwrap();
        seed_desired_supervisor(&c).unwrap();
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            Some(existing),
            "an existing pointer is left put"
        );
    }

    #[test]
    fn seed_records_the_initial_supervisor_when_none_exists() {
        let dir = temp_dir("seed-fresh");
        let initial = dir.join("supervisor");
        std::fs::write(&initial, b"binary").unwrap();
        let c = cfg(dir, Some(initial.clone()));
        seed_desired_supervisor(&c).unwrap();
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            Some(initial)
        );
    }

    #[test]
    fn a_seeded_supervisor_validates_after_the_flag_is_dropped() {
        // Regression for the seeded-initial brick: a node that seeded via `--supervisor` and then
        // had the flag removed on a later restart (before ever self-updating) must still validate
        // its committed pointer — via the durable seeded record, not the live flag.
        let dir = temp_dir("seed-flag-dropped");
        let initial = dir.join("supervisor");
        std::fs::write(&initial, b"binary").unwrap();
        // First boot: flag present, seeds the pointer + the durable seeded record.
        seed_desired_supervisor(&cfg(dir.clone(), Some(initial.clone()))).unwrap();
        // Later boot: flag dropped. Seeding re-validates the existing committed pointer.
        let no_flag = cfg(dir.clone(), None);
        seed_desired_supervisor(&no_flag).expect("committed seed must validate without the flag");
        validate_supervisor_path(&no_flag, &initial, false)
            .expect("the seeded path must validate flag-free");
    }

    #[test]
    fn seed_fails_with_no_pointer_and_no_initial() {
        let c = cfg(temp_dir("seed-none"), None);
        assert!(seed_desired_supervisor(&c).is_err());
    }

    #[test]
    fn seed_fails_when_the_initial_supervisor_does_not_exist() {
        let c = cfg(
            temp_dir("seed-missing"),
            Some(PathBuf::from("/no/such/supervisor")),
        );
        assert!(seed_desired_supervisor(&c).is_err());
    }

    #[test]
    fn seed_never_overwrites_a_corrupt_committed_pointer() {
        let state = temp_dir("seed-corrupt");
        let initial = state.join("initial-supervisor");
        std::fs::write(&initial, b"initial").unwrap();
        std::fs::write(state.join("desired-supervisor"), b"corrupt\n").unwrap();
        let c = cfg(state.clone(), Some(initial));
        assert!(seed_desired_supervisor(&c).is_err());
        assert_eq!(
            std::fs::read(state.join("desired-supervisor")).unwrap(),
            b"corrupt\n"
        );
    }
}
