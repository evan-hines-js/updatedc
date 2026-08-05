//! Stable container/host health surface owned by the permanent guardian.
//!
//! The probe state is deliberately separate from supervisor and update-transaction
//! state.  The guardian is the permanent process owner, so it is the only component
//! that can truthfully describe whether the whole tower should receive traffic or be
//! restarted:
//!
//! ```text
//!                  application accepted
//!    Starting ------------------------------> Serving
//!      |                                         | readiness lost
//!      | application/process failure             | update drain requested
//!      v                                  Unready / Draining
//!    Failed <-------------------------------------+
//!                  application/process failure    |
//!                                                  | candidate committed or
//!                                                  | predecessor restored
//!                                                  +----------------> Serving
//! ```
//!
//! `Starting`, `Unready`, and `Draining` are live but not ready. `Serving` is live and ready.
//! `Failed` is neither live nor ready and tells an outer lifecycle owner to replace
//! the tower. Startup is a latch: it becomes successful on the first transition to
//! `Serving` and stays successful across later planned drains, matching Kubernetes'
//! one-time `startupProbe` semantics.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Bound on how long a single probe connection may take to send its request or receive its
/// response. Even with each connection handled off the accept loop, an unbounded one would tie up
/// a slot indefinitely.
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(3);

/// How many probe connections may be in flight at once. Each is handled on its own short-lived
/// thread so one stalled client cannot delay a liveness or readiness probe behind it — which an
/// orchestrator reads as a failed probe and reaps the whole tower for. The cap is what keeps that
/// from becoming an unbounded thread spawn: beyond it, connections are closed immediately, which a
/// prober retries, rather than queued behind a stall.
const MAX_CONCURRENT_PROBES: usize = 16;

/// How long the accept loop waits after an accept failure that is a property of the process, not
/// of the connection it refused. Descriptor exhaustion (`EMFILE`/`ENFILE`) is the case: `accept`
/// fails instantly and keeps failing for as long as the pressure lasts, so retrying immediately
/// pins the `guardian-probes` thread at 100% CPU — on a small node, directly against the
/// guardian's one serve thread, which owes the orchestrator a readiness deadline, a stop grace,
/// and the application-exit check. Short enough that probes resume promptly once descriptors free
/// up, long enough that the loop costs nothing while they do not.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// The guardian is alive but has not accepted a healthy application yet.
    Starting = 0,
    /// The committed application is healthy and may receive traffic.
    Serving = 1,
    /// A planned lifecycle operation has withdrawn the application from traffic.
    Draining = 2,
    /// The application or its continuous liveness check failed; restart the tower.
    Failed = 3,
    /// The running application failed readiness but remains alive.
    Unready = 4,
}

#[derive(Clone)]
pub struct Machine {
    state: Arc<AtomicU8>,
    started: Arc<AtomicBool>,
}

impl Machine {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(State::Starting as u8)),
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Publish an event-derived state transition.
    ///
    /// Only the guardian calls this method. The supervisor reports authenticated
    /// lifecycle events (`TrafficReady` and `ApplicationFailed`); it cannot serve a
    /// competing probe endpoint or mutate the startup latch directly.
    pub fn transition(&self, next: State) {
        if next == State::Serving {
            self.started.store(true, Ordering::Release);
        }
        self.state.store(next as u8, Ordering::Release);
    }

    pub fn state(&self) -> State {
        match self.state.load(Ordering::Acquire) {
            1 => State::Serving,
            2 => State::Draining,
            3 => State::Failed,
            4 => State::Unready,
            _ => State::Starting,
        }
    }

    fn response(&self, path: &str) -> (u16, &'static str) {
        match path {
            "/livez" if self.state() != State::Failed => (200, "live\n"),
            "/readyz" if self.state() == State::Serving => (200, "ready\n"),
            "/startupz" if self.started.load(Ordering::Acquire) => (200, "started\n"),
            "/livez" | "/readyz" | "/startupz" => (503, "unavailable\n"),
            _ => (404, "not found\n"),
        }
    }
}

pub fn serve(address: SocketAddr, machine: Machine) -> Result<(), String> {
    let listener = TcpListener::bind(address)
        .map_err(|error| format!("binding guardian probe endpoint at {address}: {error}"))?;
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("guardian-probes".into())
        .spawn(move || {
            loop {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) => {
                        // An accept error must never kill the probe endpoint — that would fail
                        // every future probe closed and reap the tower — so the loop always keeps
                        // listening. What it must not do is keep listening at full speed on an
                        // error that will repeat: see `pause_after_accept_error`.
                        if let Some(pause) = pause_after_accept_error(error.kind()) {
                            std::thread::sleep(pause);
                        }
                        continue;
                    }
                };
                // Answer off the accept loop: a client that connects and then says nothing must
                // not sit in front of the orchestrator's next liveness probe.
                if in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_PROBES {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    continue; // dropping `stream` closes it
                }
                let machine = machine.clone();
                let done = in_flight.clone();
                let spawned = std::thread::Builder::new()
                    .name("guardian-probe".into())
                    .spawn(move || {
                        respond(&mut stream, &machine);
                        done.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            }
        })
        .map_err(|error| format!("starting guardian probe endpoint: {error}"))?;
    Ok(())
}

/// How long to wait before accepting again after an accept failed, or `None` to retry at once.
///
/// A failure that belongs to the refused connection alone — the client vanished between its SYN
/// and our accept, or a signal interrupted the call — says nothing about the next connection, and
/// the very next accept can succeed: pausing there would delay a real probe. Every other failure
/// is a property of the process (descriptor exhaustion above all) and will be returned again
/// immediately, so the retry is paced instead of spun.
fn pause_after_accept_error(kind: ErrorKind) -> Option<Duration> {
    match kind {
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted | ErrorKind::WouldBlock => None,
        _ => Some(ACCEPT_ERROR_PAUSE),
    }
}

fn respond(stream: &mut TcpStream, machine: &Machine) {
    // Never block the single probe thread on a slow or half-open client.
    let _ = stream.set_read_timeout(Some(PROBE_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_IO_TIMEOUT));
    let mut request = [0u8; 1024];
    let Ok(read) = stream.read(&mut request) else {
        return;
    };
    let first = request[..read]
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or(&[]);
    let mut fields = first.split(|byte| *byte == b' ');
    let method = fields.next().unwrap_or(&[]);
    let path = fields
        .next()
        .and_then(|value| std::str::from_utf8(value).ok());
    let (code, body) = if method == b"GET" || method == b"HEAD" {
        path.map_or((400, "bad request\n"), |path| machine.response(path))
    } else {
        (405, "method not allowed\n")
    };
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Service Unavailable",
    };
    let body = if method == b"HEAD" { "" } else { body };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_state_machine_preserves_startup_across_drains() {
        let machine = Machine::new();
        assert_eq!(machine.response("/livez").0, 200);
        assert_eq!(machine.response("/readyz").0, 503);
        assert_eq!(machine.response("/startupz").0, 503);
        machine.transition(State::Serving);
        assert_eq!(machine.response("/readyz").0, 200);
        machine.transition(State::Draining);
        assert_eq!(machine.response("/readyz").0, 503);
        assert_eq!(machine.response("/startupz").0, 200);
        machine.transition(State::Unready);
        assert_eq!(machine.response("/livez").0, 200);
        assert_eq!(machine.response("/readyz").0, 503);
        assert_eq!(machine.response("/startupz").0, 200);
        machine.transition(State::Failed);
        assert_eq!(machine.response("/livez").0, 503);
    }

    #[test]
    fn a_repeating_accept_error_is_paced_and_a_per_connection_one_is_not() {
        // Descriptor exhaustion — the case the accept loop's comment names — fails instantly and
        // keeps failing, so retrying it must cost a pause; without one the probe thread burns a
        // core for the whole outage. A client that vanished before we accepted it must not, or
        // every such connection would delay the next real probe by the pause.
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            assert_eq!(pause_after_accept_error(kind), None, "{kind:?}");
        }
        // `EMFILE`/`ENFILE` have no stable `ErrorKind` on every target, so they arrive here as
        // `Uncategorized`/`Other` — which is exactly why the pause is the default, not the
        // exception.
        for kind in [ErrorKind::Other, ErrorKind::PermissionDenied] {
            assert_eq!(
                pause_after_accept_error(kind),
                Some(ACCEPT_ERROR_PAUSE),
                "{kind:?}"
            );
        }
    }
}
