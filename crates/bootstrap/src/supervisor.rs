//! Launching and supervising the disposable supervisor process.
//!
//! The supervisor is the guardian's only child besides the application. It is
//! deliberately disposable: the guardian owns the application, so a supervisor may
//! crash, be replaced, or be updated without the application noticing. The guardian
//! launches it with an inherited control channel and a readiness nonce, then watches
//! it — serving its control requests — until it exits or is replaced.

use std::io;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use crate::rand;
use crate::sys::Channel;
use control::{Nonce, Request, Response, APP_PID_ENV, CONTROL_ENV, READY_NONCE_ENV, STATE_DIR_ENV};

const POLL: Duration = Duration::from_millis(100);

/// A launched supervisor and the guardian's end of its control channel.
pub struct Supervisor {
    child: Child,
    channel: Channel,
    nonce: Nonce,
    stop_grace: Duration,
}

impl Supervisor {
    /// Launch `binary` with an inherited control channel, the operator config path
    /// (opaque to the guardian), the state directory (for staging replacements), a fresh
    /// readiness nonce, and — if the guardian already owns a running application —
    /// its PID, so the new supervisor adopts it instead of launching a duplicate.
    pub fn launch(
        binary: &Path,
        config: &Path,
        state_dir: &Path,
        app_pid: Option<u32>,
        stop_grace: Duration,
    ) -> io::Result<Supervisor> {
        let mut channel = Channel::create()?;
        let nonce = rand::nonce();
        let mut cmd = Command::new(binary);
        cmd.arg("--config")
            .arg(config)
            .env(CONTROL_ENV, channel.child_env_value())
            .env(READY_NONCE_ENV, rand::to_hex(&nonce))
            .env(STATE_DIR_ENV, state_dir);
        match app_pid {
            Some(pid) => {
                cmd.env(APP_PID_ENV, pid.to_string());
            }
            None => {
                cmd.env_remove(APP_PID_ENV);
            }
        }
        let child = cmd.spawn()?;
        // The supervisor inherited the child end; the guardian drops its copy so it is
        // the sole holder of the guardian end (and the channel closes when the
        // supervisor dies).
        channel.close_child_end();
        Ok(Supervisor {
            child,
            channel,
            nonce,
            stop_grace,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether the supervisor has exited.
    pub fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Ask the supervisor to stop and reap it (kill on grace expiry). Never touches the
    /// application — the guardian owns that separately.
    pub fn stop(&mut self) {
        crate::sys::terminate_gracefully(self.child.id());
        let deadline = Instant::now() + self.stop_grace;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(POLL),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The guardian's control link to the supervisor it launched — exactly the surface the
/// `serve`/`dispatch` state machine uses. Abstracting it lets the serve loop, its readiness
/// gate, and every control-request transition be driven by a scripted fake in a unit test,
/// with no real process, socketpair, or clock (the same discipline the app has via
/// [`Process`](crate::sys::Process)).
pub trait Link {
    fn nonce(&self) -> Nonce;
    fn send_hello(&mut self) -> control::Result<()>;
    /// `true` when the control channel has a request buffered to read within `timeout_ms`.
    /// A timed-out or closed channel is `false`; peer death is observed via
    /// [`exited`](Self::exited), not this call.
    fn poll_readable(&self, timeout_ms: i32) -> bool;
    fn read_request(&mut self) -> control::Result<Request>;
    fn send_response(&mut self, resp: &Response) -> control::Result<()>;
    fn exited(&mut self) -> bool;
    fn stop(&mut self);
}

impl Link for Supervisor {
    fn nonce(&self) -> Nonce {
        self.nonce
    }
    fn send_hello(&mut self) -> control::Result<()> {
        self.channel.send_hello()
    }
    fn poll_readable(&self, timeout_ms: i32) -> bool {
        self.channel.poll_readable(timeout_ms)
    }
    fn read_request(&mut self) -> control::Result<Request> {
        self.channel.read_request()
    }
    fn send_response(&mut self, resp: &Response) -> control::Result<()> {
        self.channel.send_response(resp)
    }
    fn exited(&mut self) -> bool {
        Supervisor::exited(self)
    }
    fn stop(&mut self) {
        Supervisor::stop(self)
    }
}
