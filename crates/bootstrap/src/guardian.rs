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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use control::{Request, Response};

use crate::app::App;
use crate::log::{error, info, warn};
use crate::record;
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
    /// Grace before hard-killing an application or supervisor during shutdown.
    pub stop_grace: Duration,
}

/// Exponential backoff for relaunching a failed supervisor.
///
/// A supervisor that runs a healthy stretch before exiting resets it (a transient crash
/// relaunches promptly). One that keeps exiting immediately — a bricked build that cannot
/// even start, or that fails closed and cannot roll back — backs off toward the cap and
/// loops there forever, waiting for its binary to be fixed. The guardian NEVER gives up
/// and NEVER takes the application down: the app keeps running the entire time.
struct Backoff {
    consecutive: u32,
}

impl Backoff {
    const BASE: Duration = Duration::from_secs(2);
    const CAP: Duration = Duration::from_secs(5 * 60);
    /// A supervisor that ran at least this long before exiting was not a start-loop.
    const SETTLED: Duration = Duration::from_secs(30);

    fn new() -> Self {
        Backoff { consecutive: 0 }
    }

    /// The delay before the next relaunch, given how long the last supervisor ran. A run
    /// that lasted longer than [`SETTLED`](Self::SETTLED) resets the backoff to the base.
    fn next(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= Self::SETTLED {
            self.consecutive = 0;
        }
        let delay =
            foundation::time::exponential_backoff(Self::BASE, self.consecutive, 8, Self::CAP);
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
    /// The application exited on its own — roll its exit code up to the init system.
    AppCrashed(i32),
}

/// Run the guardian. Returns the process exit code: `0` for a clean stop, or the
/// application's exit code when it crashes (rolled up so the init system sees it).
pub fn run(cfg: &Config) -> Result<i32, String> {
    crate::sys::ignore_sigpipe();
    crate::sys::install_shutdown_handler();
    std::fs::create_dir_all(&cfg.state_dir)
        .map_err(|e| format!("creating state dir {}: {e}", cfg.state_dir.display()))?;
    seed_desired_supervisor(cfg)?;

    let mut app = App::none();
    let mut next: Option<PathBuf> = None; // Some(path) means "activate this candidate"
    let mut backoff = Backoff::new();
    while !crate::sys::shutdown_requested() {
        let launched = Instant::now();
        match run_supervisor(cfg, &mut app, next.take())? {
            Cycle::Stop => break,
            Cycle::Continue => {}
            Cycle::Backoff => {
                let delay = backoff.next(launched.elapsed());
                warn(&format!(
                    "relaunching the supervisor in {}s (the application keeps running)",
                    delay.as_secs()
                ));
                if sleep_interruptible(delay) {
                    break;
                }
            }
            Cycle::Activate(path) => next = Some(path),
            Cycle::AppCrashed(code) => {
                record::mark_app_crashed(&cfg.state_dir)
                    .map_err(|e| format!("recording application crash before restart: {e}"))?;
                warn(&format!(
                    "application exited (code {code}); rolling it up and letting the init system restart"
                ));
                return Ok(code);
            }
        }
    }

    // Transparent clean stop: forward it down to the application.
    info("stop requested; stopping the application and exiting");
    app.stop(cfg.stop_grace);
    Ok(0)
}

/// Launch one supervisor (the committed one, or `candidate` for a gated activation) and
/// serve it until it exits, is replaced, the app crashes, or a stop arrives.
fn run_supervisor(
    cfg: &Config,
    app: &mut App,
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

    // An application crash that landed while the guardian was between supervisors (the
    // backoff sleep, or a handoff) is only visible here — `poll_crash` runs solely inside
    // `serve()`. Surface it before adopting/launching, or the crash would be silently
    // discarded (the next `app.launch` reaps the dead proc) and the bad update relaunched
    // instead of rolled up and reverted.
    if let Some(code) = app.poll_crash() {
        return Ok(Cycle::AppCrashed(code));
    }

    // If an application is already running (a supervisor crash-relaunch, or a candidate
    // activation over the previous supervisor's app), hand its PID to the new supervisor
    // so it adopts rather than launching a duplicate.
    let app_pid = if app.is_running() { app.pid() } else { None };

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
    serve(cfg, &mut sup, app, candidate)
}

fn serve<L: Link>(
    cfg: &Config,
    sup: &mut L,
    app: &mut App,
    candidate: Option<PathBuf>,
) -> Result<Cycle, String> {
    // When activating, we must see a matching readiness ack before the deadline.
    let mut committed = candidate.is_none();
    let deadline = Instant::now() + cfg.ready_timeout;
    let mut pending_replace: Option<PathBuf> = None;

    if sup.send_hello().is_err() {
        sup.stop();
        return Ok(Cycle::Backoff);
    }

    loop {
        if crate::sys::shutdown_requested() {
            sup.stop();
            return Ok(Cycle::Stop);
        }
        if !committed && Instant::now() >= deadline {
            let path = candidate.as_ref().expect("activation has a candidate");
            warn(&format!(
                "candidate {} did not signal ready in time; rolling back and rejecting it",
                path.display()
            ));
            sup.stop();
            record::mark_rejected_supervisor(&cfg.state_dir, path).map_err(|e| {
                format!(
                    "recording timed-out supervisor {} rejection: {e}",
                    path.display()
                )
            })?;
            return Ok(Cycle::Continue);
        }

        if let crate::sys::Ready::Readable = sup.poll_readable(SERVE_POLL_MS) {
            match sup.read_request() {
                Ok(req) => {
                    if dispatch(
                        cfg,
                        sup,
                        app,
                        req,
                        candidate.as_deref(),
                        &mut committed,
                        &mut pending_replace,
                    )
                    .is_err()
                    {
                        // A channel write failed: the supervisor is gone. Fall to the
                        // exit check below.
                    }
                }
                Err(control::Error::UnknownTag(_)) => {
                    let _ = sup.send_response(&Response::Unsupported);
                }
                Err(control::Error::Closed) | Err(control::Error::Io(_)) => {}
                Err(e) => {
                    warn(&format!(
                        "supervisor sent a malformed control frame ({e}); restarting it"
                    ));
                    sup.stop();
                    return Ok(Cycle::Backoff);
                }
            }
        }

        // The application crashing takes priority: roll its code up and tear down.
        if let Some(code) = app.poll_crash() {
            sup.stop();
            return Ok(Cycle::AppCrashed(code));
        }

        if sup.exited() {
            if !committed {
                let path = candidate.as_ref().expect("activation has a candidate");
                warn(&format!(
                    "candidate {} exited before signalling ready; rejecting it",
                    path.display()
                ));
                record::mark_rejected_supervisor(&cfg.state_dir, path).map_err(|e| {
                    format!(
                        "recording exited supervisor {} rejection: {e}",
                        path.display()
                    )
                })?;
                return Ok(Cycle::Continue);
            }
            if let Some(path) = pending_replace.take() {
                info("supervisor staged a replacement and exited; activating it");
                return Ok(Cycle::Activate(path));
            }
            // The supervisor crashed but the application is fine — the guardian relaunches
            // the supervisor (with backoff) over the still-running app.
            warn("supervisor exited (the application keeps running)");
            return Ok(Cycle::Backoff);
        }
    }
}

/// Handle one control request, replying on the channel.
fn dispatch<L: Link>(
    cfg: &Config,
    sup: &mut L,
    app: &mut App,
    req: Request,
    candidate: Option<&Path>,
    committed: &mut bool,
    pending_replace: &mut Option<PathBuf>,
) -> control::Result<()> {
    let response = match req {
        Request::Launch(spec) => match app.launch(&spec, cfg.stop_grace) {
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
            app.stop(cfg.stop_grace);
            Response::Ok
        }
        Request::ReplaceSupervisor(path) => {
            // The guardian keeps no rejection set: the supervisor is responsible for not
            // re-staging a candidate it already knows failed (it read the marker). The
            // guardian just accepts the handoff and activates it when this supervisor exits.
            let path = PathBuf::from(path);
            match validate_supervisor_path(cfg, &path, true) {
                Ok(()) => {
                    *pending_replace = Some(path);
                    Response::Ok
                }
                Err(e) => Response::Error(e),
            }
        }
        Request::Ready(nonce) => {
            if !*committed && nonce == sup.nonce() {
                if let Some(path) = candidate {
                    if let Err(e) = record::set_desired_supervisor(&cfg.state_dir, path) {
                        // The candidate proved ready but we could not commit it; keep
                        // serving it uncommitted rather than dropping the channel.
                        error(&format!("committing the new supervisor failed: {e}"));
                    } else {
                        info(&format!(
                            "candidate {} proved ready; committed as the supervisor",
                            path.display()
                        ));
                        *committed = true;
                    }
                }
            }
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
    validate_supervisor_path(cfg, initial, false)?;
    record::set_desired_supervisor(&cfg.state_dir, initial)
        .map_err(|e| format!("recording the initial supervisor: {e}"))
}

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
        if let Some(initial) = &cfg.initial_supervisor {
            // Both sides must resolve: comparing `.ok()` would make two *failures* compare
            // equal (None == None) and wave the path through without ever reaching the
            // staging-directory check below.
            if let (Ok(resolved), Ok(initial)) =
                (std::fs::canonicalize(path), std::fs::canonicalize(initial))
            {
                if resolved == initial {
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
    let expected_name = if cfg!(windows) {
        "supervisor.exe"
    } else {
        "supervisor"
    };
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

/// Sleep up to `dur`, returning `true` early if a stop signal arrives.
fn sleep_interruptible(dur: Duration) -> bool {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if crate::sys::shutdown_requested() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    crate::sys::shutdown_requested()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        readable: RefCell<VecDeque<crate::sys::Ready>>,
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
        fn poll_readable(&self, _timeout_ms: i32) -> crate::sys::Ready {
            self.readable
                .borrow_mut()
                .pop_front()
                .unwrap_or(crate::sys::Ready::TimedOut)
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
            stop_grace: Duration::from_secs(10),
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
        let path = dir.join(if cfg!(windows) {
            "supervisor.exe"
        } else {
            "supervisor"
        });
        std::fs::write(&path, b"candidate").unwrap();
        path
    }

    #[test]
    fn dispatch_launch_starts_the_app_and_replies_launched() {
        let c = cfg(temp_dir("launch"), None);
        let mut sup = FakeLink::new();
        let mut app = App::with_spawn(fake_spawn);
        let (mut committed, mut pending) = (true, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Launch(spec()),
            None,
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert_eq!(sup.responses, vec![Response::Launched { pid: 4242 }]);
    }

    #[test]
    fn dispatch_stop_replies_ok() {
        let c = cfg(temp_dir("stop"), None);
        let mut sup = FakeLink::new();
        let mut app = App::with_spawn(fake_spawn);
        let (mut committed, mut pending) = (true, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Stop,
            None,
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_replace_stages_the_candidate_and_replies_ok() {
        let c = cfg(temp_dir("replace"), None);
        let mut sup = FakeLink::new();
        let mut app = App::none();
        let (mut committed, mut pending) = (true, None);
        let candidate = staged_candidate(&c, 0x11);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::ReplaceSupervisor(candidate.as_os_str().to_owned()),
            None,
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert_eq!(pending, Some(candidate));
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_replace_rejects_paths_outside_content_addressed_staging() {
        let c = cfg(temp_dir("replace-invalid"), None);
        let outside = c.state_dir.join("arbitrary-supervisor");
        std::fs::write(&outside, b"candidate").unwrap();
        let mut sup = FakeLink::new();
        let mut app = App::none();
        let (mut committed, mut pending) = (true, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::ReplaceSupervisor(outside.into_os_string()),
            None,
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert!(pending.is_none());
        assert!(matches!(sup.responses.as_slice(), [Response::Error(_)]));
    }

    #[test]
    fn dispatch_ready_with_the_matching_nonce_commits_exactly_the_candidate() {
        let c = cfg(temp_dir("ready-ok"), None);
        let cand = PathBuf::from("/state/supervisors/abc/supervisor");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut app = App::none();
        let (mut committed, mut pending) = (false, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([7u8; 16]),
            Some(&cand),
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert!(committed, "the matching nonce commits the candidate");
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            Some(cand),
            "commits exactly the candidate path"
        );
        assert_eq!(sup.responses, vec![Response::Ok]);
    }

    #[test]
    fn dispatch_ready_with_a_wrong_nonce_does_not_commit() {
        let c = cfg(temp_dir("ready-wrong"), None);
        let cand = PathBuf::from("/state/supervisors/abc/supervisor");
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        let mut app = App::none();
        let (mut committed, mut pending) = (false, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([9u8; 16]),
            Some(&cand),
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert!(!committed, "a wrong nonce must not commit");
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
        let mut app = App::none();
        let (mut committed, mut pending) = (true, None);
        dispatch(
            &c,
            &mut sup,
            &mut app,
            Request::Ready([7u8; 16]),
            Some(&cand),
            &mut committed,
            &mut pending,
        )
        .unwrap();
        assert!(
            record::desired_supervisor(&c.state_dir).unwrap().is_none(),
            "an already-committed serve never re-commits"
        );
    }

    #[test]
    fn serve_rejects_a_candidate_that_never_signals_ready_before_the_deadline() {
        let mut c = cfg(temp_dir("timeout"), None);
        c.ready_timeout = Duration::ZERO; // the deadline is already past on the first poll.
        let cand = PathBuf::from("/state/supervisors/slow/supervisor");
        let mut sup = FakeLink::new();
        let mut app = App::none();
        let cycle = serve(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
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
        let mut app = App::none();
        let cycle = serve(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(matches!(cycle, Cycle::Continue));
        assert_eq!(rejected_marker(&c).as_deref(), cand.to_str());
    }

    #[test]
    fn serve_does_not_reject_a_candidate_that_readied_then_exited() {
        let cand = PathBuf::from("/state/supervisors/good/supervisor");
        let c = cfg(temp_dir("postready"), None);
        let mut sup = FakeLink::new();
        sup.nonce = [7u8; 16];
        sup.readable
            .borrow_mut()
            .push_back(crate::sys::Ready::Readable);
        sup.requests.push_back(Request::Ready([7u8; 16]));
        sup.exited.push_back(false); // still running right after readying...
        sup.exited.push_back(true); // ...then exits
        let mut app = App::none();
        let cycle = serve(&c, &mut sup, &mut app, Some(cand.clone())).unwrap();
        assert!(
            matches!(cycle, Cycle::Backoff),
            "a committed supervisor that exits just backs off"
        );
        assert!(
            rejected_marker(&c).is_none(),
            "a committed candidate is never rejected"
        );
        assert_eq!(
            record::desired_supervisor(&c.state_dir).unwrap(),
            Some(cand),
            "and it was committed"
        );
    }

    #[test]
    fn serve_never_lets_the_deadline_reject_an_ordinary_committed_supervisor() {
        let mut c = cfg(temp_dir("committed"), None);
        c.ready_timeout = Duration::ZERO;
        let mut sup = FakeLink::new();
        sup.exited.push_back(true); // a plain committed supervisor that crashes
        let mut app = App::none();
        let cycle = serve(&c, &mut sup, &mut app, None).unwrap(); // candidate None ⇒ already committed
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
