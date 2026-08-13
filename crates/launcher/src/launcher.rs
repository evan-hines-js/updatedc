//! The launcher loop.
//!
//! The launcher manages exactly one thing: which agent binary runs. It launches the
//! agent named by the committed pointer over an inherited control channel, holds a
//! staged replacement to a readiness deadline and a confirmation window before committing
//! it, and reverts the pointer — recording a rejection by content hash — when the
//! replacement fails. It knows nothing about workloads: no process it owns exists besides
//! the agent, so an agent crash, replacement, or self-update costs nothing but the agent.
//!
//! The control loop is single-threaded: `poll` watches the control channel while the same
//! loop checks the agent process and the shutdown flag. Nothing about the agent or the
//! release state is touched from anywhere else. On Windows the control channel additionally
//! moves each write onto a scratch thread so a wedged pipe can be abandoned after a timeout;
//! that thread is fatal to the whole process if it panics (`panic = "abort"`), so it must
//! stay as small as it is.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use control::{Request, Response};

use crate::agent::{Agent, Link};
use crate::log::{error, info, warn};
use crate::record;

/// How often the serve loop wakes to re-check the agent and the shutdown flag.
const SERVE_POLL_MS: i32 = 100;

/// How long a failed control read waits for the peer to become reapable before it is called a
/// channel fault rather than an ordinary exit. Only ever spent on an agent that is already
/// finished with this channel, so it costs nothing on the healthy path. Generous next to the
/// window it closes: the kernel marks an exited child reapable as it tears the process down,
/// microseconds after the descriptor close that produced the read failure.
const EXIT_OBSERVATION_GRACE: Duration = Duration::from_millis(500);

/// The launcher's configuration, all from the command line — it parses no config file
/// (that is the agent's job; the path is passed through opaquely).
pub struct Config {
    pub state_dir: PathBuf,
    /// Operator config path, passed verbatim to every agent launch.
    pub config: PathBuf,
    /// Seed for `desired-agent` on first boot, if not already recorded.
    pub initial_agent: Option<PathBuf>,
    pub ready_timeout: Duration,
    /// How long a replacement must remain alive after proving ready before its
    /// pointer is committed. The predecessor remains authoritative throughout.
    pub confirm_timeout: Duration,
    /// Grace before hard-killing the agent during shutdown.
    pub stop_grace: Duration,
}

/// Exponential backoff for relaunching a failed agent.
///
/// An agent that runs a healthy stretch before exiting resets it (a transient crash
/// relaunches promptly). One that keeps exiting immediately — a bricked build that cannot
/// even start, or that fails closed and cannot roll back — backs off toward the cap and
/// loops there forever, waiting for its binary to be fixed. The launcher NEVER gives up.
///
/// The reset is rate-limited, and that is what makes the relaunch loop bounded for the case a
/// duration test alone cannot see: an agent that fails *late*. Boot reconciliation can spend
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
    /// An agent that ran at least this long before exiting was not a start-loop.
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

    /// The crash-loop base delay. Tunable via `UPDATED_LAUNCHER_BACKOFF_BASE_MS` so a test can
    /// widen the backoff window enough that a shutdown deterministically lands inside the sleep
    /// (never in the brief serve window) — no wall-clock margin to flake. Defaults to [`BASE`].
    fn base() -> Duration {
        std::env::var("UPDATED_LAUNCHER_BACKOFF_BASE_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Self::BASE)
    }

    /// The delay before the next relaunch, given how long the last agent ran. A run that
    /// lasted longer than [`SETTLED`](Self::SETTLED) resets the backoff to the base — unless this
    /// is already the [`BURST`](Self::BURST)+1st relaunch of the current
    /// [`WINDOW`](Self::WINDOW), in which case nothing resets it and the delay keeps climbing to
    /// the cap. That is the launcher's whole bound on relaunch rate; nothing else throttles an
    /// agent that exits to be relaunched.
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

/// What to do after one agent lifetime ends.
enum Cycle {
    /// Relaunch the committed agent.
    Continue,
    /// Relaunch it, but pause first (crash-loop guard).
    Backoff,
    /// A stop signal arrived; exit.
    Stop,
    /// The agent staged a replacement and exited; activate it under a readiness gate.
    Activate(PathBuf),
}

/// Run the launcher until a stop signal arrives.
pub fn run(cfg: &Config) -> Result<(), String> {
    crate::sys::ignore_sigpipe();
    crate::sys::install_shutdown_handler();
    std::fs::create_dir_all(&cfg.state_dir)
        .map_err(|e| format!("creating state dir {}: {e}", cfg.state_dir.display()))?;
    // Reap any half-written record temp orphaned by a prior crash between write and rename,
    // before we start dropping fresh ones. Best-effort hygiene, never a correctness gate.
    let swept = foundation::durable::sweep_stale_temps(&cfg.state_dir, ".launcher-");
    if swept > 0 {
        info(&format!("swept {swept} stale state temp file(s)"));
    }
    seed_desired_agent(cfg)?;

    let mut next: Option<PathBuf> = None; // Some(path) means "activate this candidate"
    let mut backoff = Backoff::new();
    while !crate::sys::shutdown_requested() {
        let launched = Instant::now();
        // A failed agent cycle must not take the launcher down with it. The launcher's own exit
        // leaves the node with no agent at all until the init system restarts it — into the same
        // transient durable-state failure (ENOSPC or EIO recording a rejection, an unwritable
        // state dir) that ended this cycle. Log it, back off, and try the cycle again. Startup
        // failures that genuinely cannot be recovered from happen before this loop.
        let candidate = next.take();
        let cycle = match run_agent(cfg, candidate.clone()) {
            Ok(cycle) => cycle,
            Err(error) => {
                warn(&format!(
                    "agent cycle failed ({error}); the cycle is retried"
                ));
                if let Some(path) = &candidate {
                    reject_dropped_candidate(cfg, path);
                }
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
                // committed agent. Advance the SAME backoff here so a candidate that
                // passes `send_hello` but fast-crashes before `Ready` cannot drive an
                // unthrottled relaunch loop: the launcher is the backstop and must
                // rate-limit on its own, independent of any agent-side policy. Quiet
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
        }
    }

    info("stop requested; exiting");
    Ok(())
}

/// Launch one agent (the committed one, or `candidate` for a gated activation) and
/// serve it until it exits, is replaced, or a stop arrives.
fn run_agent(cfg: &Config, candidate: Option<PathBuf>) -> Result<Cycle, String> {
    let binary = match &candidate {
        Some(path) => path.clone(),
        None => record::desired_agent(&cfg.state_dir)
            .map_err(|e| format!("reading committed agent pointer: {e}"))?
            .ok_or_else(|| "no committed agent recorded and none supplied (--agent)".to_string())?,
    };
    validate_agent_path(cfg, &binary, candidate.is_some())?;

    let mut sup = match Agent::launch(&binary, &cfg.config, &cfg.state_dir, cfg.stop_grace) {
        Ok(sup) => sup,
        Err(e) => {
            if let Some(path) = &candidate {
                warn(&format!(
                    "candidate agent {} could not be launched ({e}); rejecting",
                    path.display()
                ));
                record::mark_rejected_agent(&cfg.state_dir, path).map_err(|marker| {
                    format!("candidate {} failed to launch ({e}) and recording its rejection failed: {marker}", path.display())
                })?;
                return Ok(Cycle::Continue);
            }
            error(&format!(
                "cannot launch committed agent {}: {e}",
                binary.display()
            ));
            return Ok(Cycle::Backoff);
        }
    };
    info(&format!(
        "launched agent {} (pid {}){}",
        binary.display(),
        sup.pid(),
        if candidate.is_some() {
            " under a readiness gate"
        } else {
            ""
        }
    ));
    serve_service(cfg, &mut sup, candidate)
}

fn serve_service<L: Link>(
    cfg: &Config,
    sup: &mut L,
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
                    if dispatch(cfg, sup, req, &mut activation).is_err() {
                        // A response write failed — a partial/timed-out frame may already be on the
                        // wire. Never keep serving this channel: the very next response would land
                        // after a half-written one and desync the agent's frame reader (and on
                        // Windows an abandoned write thread could interleave bytes). Stop the
                        // agent and relaunch it on a fresh channel rather than trusting the
                        // peer to eventually exit on its own.
                        sup.stop();
                        return conclude(cfg, &mut activation, "could not be written to");
                    }
                }
                // Forward compatibility, not a fault: a newer agent may send a tag this
                // launcher has never heard of. Answer `Unsupported` and keep serving — but a
                // failed write here leaves the same half-written frame the dispatch arm above
                // refuses to serve past, so it ends the channel the same way.
                Err(control::Error::UnknownTag(_)) => {
                    if sup.send_response(&Response::Unsupported).is_err() {
                        sup.stop();
                        return conclude(cfg, &mut activation, "could not be written to");
                    }
                }
                // Any other read failure ends this agent's usefulness, so it ends its
                // lifetime — through the same `conclude` every other ending goes through.
                //
                // The common cause is the ordinary one: the agent EXITED, and on Unix its
                // closed socketpair reports readable-with-hangup forever, so the read fails on
                // the very poll that would otherwise observe the exit. That is not a channel
                // fault and must not be logged or reported as one.
                //
                // An agent still RUNNING without a usable channel is the real fault, and it
                // must not be left running: `poll_readable` would return immediately on every
                // iteration and pin a core at 100% for as long as it lives.
                //
                // Which of the two it is must be decided by `exited_within`, never by sampling
                // liveness once: EOF arrives when the peer's descriptors close, but the exit is
                // not reapable until a moment later, so a single sample reports an ordinary exit
                // as a channel fault at random.
                Err(error) => {
                    let reason = if sup.exited_within(EXIT_OBSERVATION_GRACE) {
                        "exited"
                    } else {
                        warn(&format!(
                            "the agent's control channel is unusable ({error}); stopping it"
                        ));
                        sup.stop();
                        "lost its control channel"
                    };
                    return conclude(cfg, &mut activation, reason);
                }
            }
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
            match record::set_desired_agent(&cfg.state_dir, path) {
                Ok(()) => info(&format!(
                    "candidate {} survived its confirmation window; committed as the agent",
                    path.display()
                )),
                // The pointer moved and only the fsync proving it durable failed. Rolling back
                // here would reject a candidate the on-disk pointer already names, so the next
                // cycle would launch it as the committed agent — no readiness gate, no
                // confirmation window — with a rejection marker about itself on disk.
                Err(e) if foundation::durable::committed_unsynced(&e) => warn(&format!(
                    "candidate {} is committed as the agent, but the commit could not be \
                     proved durable: {e}",
                    path.display()
                )),
                Err(e) => {
                    error(&format!(
                        "committing stable agent {} failed: {e}; reverting to its predecessor",
                        path.display()
                    ));
                    sup.stop();
                    return conclude(cfg, &mut activation, "could not be committed");
                }
            }
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

/// End one agent's lifetime and decide what the launcher does next. `reason` completes the
/// sentence "the agent/candidate …" in the log line.
///
/// EVERY way of leaving [`serve_service`] short of a stop signal funnels through here — the
/// process exited, its channel died, it never signalled ready, its commit failed — because two
/// obligations must not depend on which of those happened:
///
///  * An uncommitted candidate is ALWAYS recorded rejected. Its bytes live in a
///    content-addressed slot, so an agent that is not told the hash failed re-selects it,
///    re-stages it into the same slot, and hands it off again, forever.
///  * A staged replacement is ALWAYS activated. Dropping it means self-update silently never
///    completes: the committed agent comes back, re-stages the same candidate, and the
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
        record::mark_rejected_agent(&cfg.state_dir, path).map_err(|e| {
            format!(
                "recording rejection of agent {} ({reason}): {e}",
                path.display()
            )
        })?;
        return Ok(Cycle::Continue);
    }
    if let Some(path) = activation.pending_replace.take() {
        info(&format!(
            "agent {reason} after staging a replacement; activating {}",
            path.display()
        ));
        return Ok(Cycle::Activate(path));
    }
    warn(&format!("agent {reason}; relaunching it"));
    Ok(Cycle::Backoff)
}

/// Record the rejection of a candidate the cycle consumed but never launched — the one ending
/// that does not pass through [`conclude`].
///
/// A cycle that fails (`run_agent` returning `Err`) is retried rather than fatal, so the
/// candidate it took is simply gone; without a marker, the always-reject invariant `conclude`
/// documents would hold for every ending but this one, and the committed agent would come
/// back, re-select the same release, re-stage the same content-addressed bytes and hand them off
/// again, forever. `run_agent` can only fail before a candidate is committed (every path
/// after the commit returns `Ok`), so a candidate it dropped is always an uncommitted one.
///
/// A failed marker write is logged, never propagated: taking the launcher down over a
/// durable-state failure is the outcome the retry loop exists to avoid. The next cycle re-stages
/// and re-rejects, and the write is retried with it.
fn reject_dropped_candidate(cfg: &Config, path: &Path) {
    warn(&format!(
        "candidate {} was dropped by a failed agent cycle; rejecting it",
        path.display()
    ));
    if let Err(e) = record::mark_rejected_agent(&cfg.state_dir, path) {
        error(&format!(
            "recording rejection of dropped candidate {}: {e}",
            path.display()
        ));
    }
}

/// Handle one control request, replying on the channel.
fn dispatch<L: Link>(
    cfg: &Config,
    sup: &mut L,
    req: Request,
    activation: &mut ActivationState,
) -> control::Result<()> {
    let response = match req {
        Request::ReplaceAgent(path) => {
            // The launcher keeps no rejection set: the agent is responsible for not
            // re-staging a candidate it already knows failed (it read the marker). The
            // launcher just accepts the handoff and activates it when this agent exits.
            let path = PathBuf::from(path);
            match validate_agent_path(cfg, &path, true) {
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
    };
    sup.send_response(&response)
}

/// On first boot, record the supplied initial agent as the committed one.
fn seed_desired_agent(cfg: &Config) -> Result<(), String> {
    if let Some(committed) = record::desired_agent(&cfg.state_dir)
        .map_err(|e| format!("reading committed agent pointer: {e}"))?
    {
        return validate_agent_path(cfg, &committed, false);
    }
    let initial = cfg
        .initial_agent
        .as_ref()
        .ok_or("no committed agent and no --agent to seed one")?;
    // Durably record the seeded path BEFORE the pointer, so a later boot trusts it flag-free (see
    // `validate_agent_path`). A crash between the two just re-seeds identically next boot.
    record::set_seeded_agent(&cfg.state_dir, initial)
        .map_err(|e| format!("recording the seeded agent: {e}"))?;
    validate_agent_path(cfg, initial, false)?;
    record::set_desired_agent(&cfg.state_dir, initial)
        .map_err(|e| format!("recording the initial agent: {e}"))
}

/// Validate that `path` is a safe agent binary to launch (a regular non-symlink file
/// inside the content-addressed staging tree, or the durably-seeded initial path).
///
/// This is a TOCTOU check: the file could in principle be swapped between this validation
/// and the subsequent `Agent::launch`. The window is acceptable and bounded because
/// the staging tree lives under the launcher's own root-owned `state_dir` — an attacker who
/// could rewrite content-addressed paths there already owns the node — and because the path
/// is content-addressed (`agents/<sha256>/…`), so a swap that preserved the hash
/// directory name would have to preserve the bytes. The check exists to reject
/// misconfiguration and stray symlinks, not to defend a hostile-writer race, so re-opening
/// atomically to close the window would buy nothing.
fn validate_agent_path(cfg: &Config, path: &Path, candidate: bool) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("inspecting agent {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "agent {} must be a regular, non-symlink file",
            path.display()
        ));
    }
    if !candidate {
        // Trust a non-staging committed path only if it matches the DURABLE seeded record (written
        // at first boot while `--agent` was present) — not the live `--agent` flag. This
        // means the flag can be dropped on any later restart without bricking a node that has never
        // self-updated (its committed pointer is still the installer-placed raw path). A node that
        // HAS self-updated has a staging-tree pointer and never reaches here.
        if let Ok(Some(seeded)) = record::seeded_agent(&cfg.state_dir) {
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
        .map_err(|e| format!("canonicalizing agent {}: {e}", path.display()))?;
    let root = std::fs::canonicalize(cfg.state_dir.join("agents"))
        .map_err(|e| format!("canonicalizing agent staging directory: {e}"))?;
    let relative = canonical.strip_prefix(&root).map_err(|_| {
        format!(
            "agent {} is outside the managed staging directory",
            path.display()
        )
    })?;
    let parts: Vec<_> = relative.components().collect();
    let expected_name = foundation::platform::agent_binary_name();
    if parts.len() != 2
        || parts[0]
            .as_os_str()
            .to_str()
            .is_none_or(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        || parts[1].as_os_str() != expected_name
    {
        return Err(format!(
            "agent {} must be agents/<64-hex-sha256>/{expected_name}",
            path.display()
        ));
    }
    Ok(())
}

/// Advance the relaunch backoff and sleep it out before the next agent launch.
/// Returns `true` if a stop cut the sleep short (the caller then exits without relaunching).
///
/// Both the crash-loop path (`Cycle::Backoff`) and the candidate-rejection path
/// (`Cycle::Continue`) funnel through here so relaunch is throttled the same way regardless
/// of which one triggered it. `announce` logs the wait for the crash-loop case; the
/// candidate-rejection case stays quiet to avoid a warning on every routine rejection.
fn backoff_pause(backoff: &mut Backoff, ran_for: Duration, announce: bool) -> bool {
    let delay = backoff.next(ran_for);
    if announce {
        warn(&format!("relaunching the agent in {}s", delay.as_secs()));
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

    const INSTANT: Duration = Duration::from_millis(10); // an agent that died at once

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
        // `Cycle::Continue`. The launcher must throttle the resulting relaunch itself rather
        // than trust agent policy, so every rejection cycle advances the shared backoff.
        // A zero base makes the pause a no-op sleep, so the test asserts the advance without
        // a wall-clock delay.
        let mut backoff = Backoff::with_base(Duration::ZERO);
        assert_eq!(backoff.consecutive, 0);
        for expected in 1..=4 {
            // announce = false is exactly the candidate-rejection (Cycle::Continue) path.
            assert!(
                !backoff_pause(&mut backoff, INSTANT, false),
                "no shutdown, so the pause completes and the launcher relaunches"
            );
            assert_eq!(
                backoff.consecutive, expected,
                "each candidate-rejection cycle advances the backoff, throttling the relaunch"
            );
        }
    }

    #[test]
    fn an_agent_that_ran_a_while_resets_the_backoff() {
        let mut b = Backoff::new();
        b.next(INSTANT);
        b.next(INSTANT);
        b.next(INSTANT); // backed off a few times

        // An agent that ran past the settle threshold before exiting is a transient crash,
        // not a start-loop: the next relaunch is prompt again.
        assert_eq!(b.next(Backoff::SETTLED), Duration::from_secs(2));
    }

    #[test]
    fn an_agent_that_fails_late_on_every_cycle_still_backs_off() {
        // The path this bound exists for: the agent exits for relaunch AFTER a long boot —
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

        // A new window starts fresh: a node whose agent fails once an hour is not a loop,
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

    /// A scripted agent control link: poll/read/exit results are queues consumed
    /// front-to-back; sent responses and stop calls are captured for assertions.
    struct FakeLink {
        nonce: control::Nonce,
        hello_ok: bool,
        readable: RefCell<VecDeque<bool>>,
        requests: VecDeque<control::Request>,
        exited: VecDeque<bool>,
        /// This peer never exits, however long it is observed — the "still running without a
        /// usable channel" case, which the finite `exited` script cannot express.
        stays_alive: bool,
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
                stays_alive: false,
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
            // A peer that never exits is a property no finite script can state: `exited_within`
            // polls until its grace expires, so a scripted `false` would be consumed and fall
            // through to the exhaustion fallback below.
            if self.stays_alive {
                return false;
            }
            // Script exhaustion is an agent exit. This gives every state-machine test
            // a finite fallback: a broken deadline is reported by the assertions instead
            // of hanging the mutation runner forever.
            self.exited.pop_front().unwrap_or(true)
        }
        fn stop(&mut self) {
            self.stops += 1;
        }
    }

    fn temp_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let d = guard.path().join(tag);
        std::fs::create_dir_all(&d).unwrap();
        (guard, d)
    }

    fn cfg(state_dir: PathBuf, initial: Option<PathBuf>) -> Config {
        Config {
            state_dir,
            config: PathBuf::from("/etc/agent.toml"),
            initial_agent: initial,
            ready_timeout: Duration::from_secs(30),
            confirm_timeout: Duration::from_secs(30),
            stop_grace: Duration::from_secs(10),
        }
    }

    fn rejected_marker(c: &Config) -> Option<String> {
        std::fs::read_to_string(c.state_dir.join(control::REJECTED_AGENT_FILE)).ok()
    }

    fn staged_candidate(c: &Config, byte: u8) -> PathBuf {
        let digest = format!("{byte:02x}").repeat(32);
        let dir = c.state_dir.join("agents").join(digest);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(foundation::platform::agent_binary_name());
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
    fn dispatch_replace_stages_the_candidate_and_replies_ok() {
        let (_tmp, state_dir) = temp_dir("replace");
        let c = cfg(state_dir, None);
        let mut sup = FakeLink::new();
        let mut state = activation(None, true);
        let candidate = staged_candidate(&c, 0x11);
        dispatch(
            &c,
            &mut sup,
            Request::ReplaceAgent(candidate.as_os_str().to_owned()),
            &mut state,
        )
        .unwrap();
        assert_eq!(state.pending_replace, Some(candidate));
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_replace_rejects_paths_outside_content_addressed_staging() {
        let (_tmp, state_dir) = temp_dir("replace-invalid");
        let c = cfg(state_dir, None);
        let outside = c.state_dir.join("arbitrary-agent");
        std::fs::write(&outside, b"candidate").unwrap();
        let mut sup = FakeLink::new();
        let mut state = activation(None, true);
        dispatch(
            &c,
            &mut sup,
            Request::ReplaceAgent(outside.into_os_string()),
            &mut state,
        )
        .unwrap();
        assert!(state.pending_replace.is_none());
        assert!(matches!(sup.responses.as_slice(), [Response::Error(_)]));
    }

    #[test]
    fn dispatch_ready_with_the_matching_nonce_begins_confirmation() {
        let (_tmp, state_dir) = temp_dir("ready-ok");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/abc/agent");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut state = activation(Some(cand), false);
        dispatch(&c, &mut sup, Request::Ready([7u8; 16]), &mut state).unwrap();
        assert!(
            !state.committed,
            "readiness alone must not commit the candidate"
        );
        assert!(state.ready_since.is_some(), "the stability window begins");
        assert!(record::desired_agent(&c.state_dir).unwrap().is_none());
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_ready_with_a_wrong_nonce_does_not_commit() {
        let (_tmp, state_dir) = temp_dir("ready-wrong");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/abc/agent");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut state = activation(Some(cand), false);
        dispatch(&c, &mut sup, Request::Ready([9u8; 16]), &mut state).unwrap();
        assert!(!state.committed, "a wrong nonce must not commit");
        assert!(state.ready_since.is_none());
        assert!(
            record::desired_agent(&c.state_dir).unwrap().is_none(),
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
        let (_tmp, state_dir) = temp_dir("ready-committed");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/abc/agent");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut state = activation(Some(cand), true);
        dispatch(&c, &mut sup, Request::Ready([7u8; 16]), &mut state).unwrap();
        assert!(
            record::desired_agent(&c.state_dir).unwrap().is_none(),
            "an already-committed serve never re-commits"
        );
    }

    #[test]
    fn an_exited_agents_closed_channel_still_activates_its_staged_replacement() {
        // On Unix an exited agent leaves its socketpair readable-with-hangup, so the read
        // fails with `Closed` on the very poll that would otherwise observe the exit. Treating
        // that as a channel fault discarded the staged replacement — self-update silently never
        // activated, and the old agent came back every time.
        let (_tmp, state_dir) = temp_dir("closed-after-replace");
        let c = cfg(state_dir, None);
        let staged = staged_candidate(&c, 0x22);
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true); // ReplaceAgent arrives
        sup.readable.borrow_mut().push_back(true); // then the channel reads as closed
        sup.requests
            .push_back(Request::ReplaceAgent(staged.clone().into_os_string()));
        sup.exited.push_back(false); // still running when it staged the replacement

        let cycle = serve_service(&c, &mut sup, None).unwrap();
        assert!(
            matches!(cycle, Cycle::Activate(path) if path == staged),
            "the staged replacement must still be activated"
        );
    }

    #[test]
    fn an_exited_candidates_closed_channel_still_rejects_it() {
        // Same Unix readable-with-hangup read failure, seen while gating a candidate: the
        // rejection marker is what stops the agent re-selecting and re-staging the same
        // content-addressed bytes forever, so it must be written on this path too.
        let (_tmp, state_dir) = temp_dir("closed-candidate");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/dead/agent");
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true); // readable-with-hangup, nothing to read

        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn a_candidate_dropped_by_a_failed_cycle_is_still_rejected() {
        // The one ending that does not pass through `conclude`: the staged slot vanishes between
        // the `ReplaceAgent` validation and the activation, so `run_agent` fails before
        // it can launch anything and the run loop retries the cycle. The candidate is consumed
        // either way, so its rejection must be recorded here too — otherwise the committed
        // agent re-selects the same release, re-stages the same content-addressed bytes and
        // hands them off again, forever, with nothing on disk saying it failed.
        let (_tmp, state_dir) = temp_dir("dropped-candidate");
        let c = cfg(state_dir, None);
        let cand = staged_candidate(&c, 0xa1);
        std::fs::remove_file(&cand).unwrap();

        assert!(
            run_agent(&c, Some(cand.clone())).is_err(),
            "a candidate whose staged slot vanished fails the cycle"
        );
        assert!(
            rejected_marker(&c).is_none(),
            "the failed cycle itself records nothing — the run loop must"
        );
        reject_dropped_candidate(&c, &cand);
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn a_running_agent_that_loses_its_channel_is_stopped() {
        // A live agent without a usable channel would spin `poll_readable` at 100% forever.
        // It is stopped and relaunched on a fresh one.
        let (_tmp, state_dir) = temp_dir("channel-lost");
        let c = cfg(state_dir, None);
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true);
        sup.stays_alive = true; // still running when the read fails, and stays that way

        let cycle = serve_service(&c, &mut sup, None).unwrap();
        assert!(matches!(cycle, Cycle::Backoff));
        assert_eq!(sup.stops, 1, "the agent is stopped, not left spinning");
        assert!(rejected_marker(&c).is_none(), "nothing to reject");
    }

    #[test]
    fn a_candidate_that_loses_its_channel_while_running_is_rejected() {
        let (_tmp, state_dir) = temp_dir("channel-lost-candidate");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/mute/agent");
        let mut sup = FakeLink::new();
        sup.readable.borrow_mut().push_back(true);
        sup.stays_alive = true;

        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(
            rejected_marker(&c).as_deref(),
            cand.to_str(),
            "a candidate that cannot be talked to is rejected, not retried forever"
        );
    }

    #[test]
    fn a_hello_that_fails_rejects_a_candidate_and_only_backs_off_a_committed_agent() {
        let (_tmp, state_dir) = temp_dir("hello-candidate");
        let c = cfg(state_dir, None);
        let cand = PathBuf::from("/state/agents/mismatch/agent");
        let mut sup = FakeLink::new();
        sup.hello_ok = false;
        assert!(matches!(
            serve_service(&c, &mut sup, Some(cand.clone())).unwrap(),
            Cycle::Continue
        ));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());

        let (_tmp, state_dir) = temp_dir("hello-committed");
        let c = cfg(state_dir, None);
        let mut sup = FakeLink::new();
        sup.hello_ok = false;
        assert!(matches!(
            serve_service(&c, &mut sup, None).unwrap(),
            Cycle::Backoff
        ));
        assert!(rejected_marker(&c).is_none());
    }

    #[test]
    fn serve_rejects_a_candidate_that_never_signals_ready_before_the_deadline() {
        let (_tmp, state_dir) = temp_dir("timeout");
        let mut c = cfg(state_dir, None);
        c.ready_timeout = Duration::ZERO; // the deadline is already past on the first poll.
        let cand = PathBuf::from("/state/agents/slow/agent");
        let mut sup = FakeLink::new();
        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(
            matches!(cycle, Cycle::Continue),
            "a timed-out candidate rolls back to the committed agent"
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
        let cand = PathBuf::from("/state/agents/dead/agent");
        let (_tmp, state_dir) = temp_dir("preexit");
        let c = cfg(state_dir, None);
        let mut sup = FakeLink::new();
        sup.exited.push_back(true); // exits before any Ready
        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn serve_rejects_a_candidate_that_exits_during_confirmation() {
        let cand = PathBuf::from("/state/agents/good/agent");
        let (_tmp, state_dir) = temp_dir("postready");
        let c = cfg(state_dir, None);
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false); // still running right after readying...
        sup.exited.push_back(true); // ...then exits
        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(
            matches!(cycle, Cycle::Continue),
            "an unconfirmed agent rolls back immediately"
        );
        assert!(
            rejected_marker(&c).as_deref() == cand.to_str(),
            "an unstable candidate is rejected"
        );
        assert_eq!(
            record::desired_agent(&c.state_dir).unwrap(),
            None,
            "an unstable candidate must never become desired"
        );
    }

    #[test]
    fn serve_commits_only_after_the_confirmation_window() {
        let cand = PathBuf::from("/state/agents/stable/agent");
        let (_tmp, state_dir) = temp_dir("confirmed");
        let mut c = cfg(state_dir, None);
        c.confirm_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false);
        sup.exited.push_back(true);
        let cycle = serve_service(&c, &mut sup, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Backoff));
        assert_eq!(record::desired_agent(&c.state_dir).unwrap(), Some(cand));
        assert!(rejected_marker(&c).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_commit_that_moved_the_pointer_is_never_rolled_back() {
        // The rollback exists for a commit that did NOT happen. A durable write can also fail
        // after its rename — the pointer moved, only the fsync proving it durable failed — and
        // rejecting the candidate then leaves a rejection marker about the exact binary the next
        // boot launches as the committed agent, ungated and unconfirmed.
        use std::os::unix::fs::PermissionsExt;
        let cand = PathBuf::from("/state/agents/unsynced/agent");
        let (_tmp, state_dir) = temp_dir("commit-unsynced");
        let mut c = cfg(state_dir, None);
        c.confirm_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false);
        sup.exited.push_back(true);
        // Write and search but not read: the pointer's temp+rename still commits, the state
        // directory's own fsync cannot. Root bypasses the check, so there is nothing to prove.
        let root = unsafe { libc::geteuid() } == 0;
        std::fs::set_permissions(&c.state_dir, PermissionsExt::from_mode(0o300)).unwrap();
        let cycle = serve_service(&c, &mut sup, Some(cand.clone()));
        std::fs::set_permissions(&c.state_dir, PermissionsExt::from_mode(0o700)).unwrap();
        if root {
            return;
        }
        assert!(
            matches!(cycle.unwrap(), Cycle::Backoff),
            "a committed agent that later exits is relaunched, not rejected"
        );
        assert_eq!(record::desired_agent(&c.state_dir).unwrap(), Some(cand));
        assert!(
            rejected_marker(&c).is_none(),
            "the candidate the pointer names must never be recorded rejected"
        );
    }

    #[test]
    fn exit_at_confirmation_deadline_loses_to_liveness_check() {
        let cand = PathBuf::from("/state/agents/racy/agent");
        let (_tmp, state_dir) = temp_dir("confirmation-race");
        let mut c = cfg(state_dir, None);
        c.confirm_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable.borrow_mut().push_back(true);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(true);
        assert!(matches!(
            serve_service(&c, &mut sup, Some(cand.clone())).unwrap(),
            Cycle::Continue
        ));
        assert_eq!(record::desired_agent(&c.state_dir).unwrap(), None);
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn serve_never_lets_the_deadline_reject_an_ordinary_committed_agent() {
        let (_tmp, state_dir) = temp_dir("committed");
        let mut c = cfg(state_dir, None);
        c.ready_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.exited.push_back(true); // a plain committed agent that crashes
        let cycle = serve_service(&c, &mut sup, None).unwrap(); // candidate None ⇒ already committed
        assert!(
            matches!(cycle, Cycle::Backoff),
            "a committed agent is never rejected by the readiness deadline"
        );
        assert!(rejected_marker(&c).is_none());
    }

    #[test]
    fn seed_preserves_an_existing_desired_pointer() {
        let (_tmp, state) = temp_dir("seed-existing");
        let initial = state.join("initial-agent");
        std::fs::write(&initial, b"initial").unwrap();
        let c = cfg(state, Some(initial));
        let existing = staged_candidate(&c, 0x22);
        record::set_desired_agent(&c.state_dir, &existing).unwrap();
        seed_desired_agent(&c).unwrap();
        assert_eq!(
            record::desired_agent(&c.state_dir).unwrap(),
            Some(existing),
            "an existing pointer is left put"
        );
    }

    #[test]
    fn seed_records_the_initial_agent_when_none_exists() {
        let (_tmp, dir) = temp_dir("seed-fresh");
        let initial = dir.join("agent");
        std::fs::write(&initial, b"binary").unwrap();
        let c = cfg(dir, Some(initial.clone()));
        seed_desired_agent(&c).unwrap();
        assert_eq!(record::desired_agent(&c.state_dir).unwrap(), Some(initial));
    }

    #[test]
    fn a_seeded_agent_validates_after_the_flag_is_dropped() {
        // Regression for the seeded-initial brick: a node that seeded via `--agent` and then
        // had the flag removed on a later restart (before ever self-updating) must still validate
        // its committed pointer — via the durable seeded record, not the live flag.
        let (_tmp, dir) = temp_dir("seed-flag-dropped");
        let initial = dir.join("agent");
        std::fs::write(&initial, b"binary").unwrap();
        // First boot: flag present, seeds the pointer + the durable seeded record.
        seed_desired_agent(&cfg(dir.clone(), Some(initial.clone()))).unwrap();
        // Later boot: flag dropped. Seeding re-validates the existing committed pointer.
        let no_flag = cfg(dir.clone(), None);
        seed_desired_agent(&no_flag).expect("committed seed must validate without the flag");
        validate_agent_path(&no_flag, &initial, false)
            .expect("the seeded path must validate flag-free");
    }

    #[test]
    fn seed_fails_with_no_pointer_and_no_initial() {
        let (_tmp, state_dir) = temp_dir("seed-none");
        let c = cfg(state_dir, None);
        assert!(seed_desired_agent(&c).is_err());
    }

    #[test]
    fn seed_fails_when_the_initial_agent_does_not_exist() {
        let (_tmp, state_dir) = temp_dir("seed-missing");
        let c = cfg(state_dir, Some(PathBuf::from("/no/such/agent")));
        assert!(seed_desired_agent(&c).is_err());
    }

    #[test]
    fn seed_never_overwrites_a_corrupt_committed_pointer() {
        let (_tmp, state) = temp_dir("seed-corrupt");
        let initial = state.join("initial-agent");
        std::fs::write(&initial, b"initial").unwrap();
        std::fs::write(state.join("desired-agent"), b"corrupt\n").unwrap();
        let c = cfg(state.clone(), Some(initial));
        assert!(seed_desired_agent(&c).is_err());
        assert_eq!(
            std::fs::read(state.join("desired-agent")).unwrap(),
            b"corrupt\n"
        );
    }
}
