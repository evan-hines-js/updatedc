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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Bound on how long a single probe connection may take to send its request or receive its
/// response. The endpoint is served serially on one thread, so without this a single stalled
/// client would wedge every subsequent liveness/readiness probe and get the whole tower reaped.
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(3);

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
    std::thread::Builder::new()
        .name("guardian-probes".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => respond(&mut stream, &machine),
                    // A transient accept error (e.g. fd exhaustion) must not permanently kill the
                    // probe endpoint — that would fail every future probe closed and reap the
                    // tower. Skip this connection and keep listening.
                    Err(_) => continue,
                }
            }
        })
        .map_err(|error| format!("starting guardian probe endpoint: {error}"))?;
    Ok(())
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
}
