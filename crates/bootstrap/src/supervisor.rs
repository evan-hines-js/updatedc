//! Launching and supervising the disposable supervisor process.
//!
//! The supervisor is the guardian's only child besides the application. It is
//! deliberately disposable: the guardian owns the application, so a supervisor may
//! crash, be replaced, or be updated without the application noticing. The guardian
//! launches it with an inherited control channel and a readiness nonce, then watches
//! it — serving its control requests — until it exits or is replaced.

use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use foundation::process::ContainedChild;

use crate::rand;
use crate::sys::Channel;
use control::{Nonce, Request, Response, APP_PID_ENV, CONTROL_ENV, READY_NONCE_ENV, STATE_DIR_ENV};

const POLL: Duration = Duration::from_millis(100);

/// A launched supervisor and the guardian's end of its control channel. The supervisor is
/// death-contained ([`ContainedChild`]): a SIGKILLed guardian can never orphan it — on
/// Linux `PR_SET_PDEATHSIG` has the kernel kill it, on Windows the kill-on-close job object
/// ties its lifetime to the guardian's handle.
pub struct Supervisor {
    child: ContainedChild,
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
        // Death-contain the supervisor so a SIGKILLed guardian can never orphan it — it is
        // the guardian's disposable child, exactly the "churning tower" case `ContainedChild`
        // exists for. On Linux `arrange_parent_death_signal` adds `PR_SET_PDEATHSIG`; on
        // Windows the kill-on-close job `ContainedChild` assigns ties the supervisor to the
        // guardian's handle. The process group a graceful `CTRL_BREAK`/`SIGTERM` needs is
        // `ContainedChild`'s own doing on both platforms — see `ContainedChild::request_stop`.
        foundation::process::arrange_parent_death_signal(&mut cmd);
        let child = ContainedChild::spawn(cmd)?;
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

    /// Whether the supervisor has exited, sampled now.
    pub fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Ask the supervisor to stop and reap it (kill on grace expiry). Never touches the
    /// application — the guardian owns that separately.
    ///
    /// Both the graceful request and the hard kill go through [`ContainedChild`], which knows
    /// whether the leader has already been reaped. A raw `kill(pid, …)` here would be the same
    /// recycled-PID hazard `kill_tree` was built to remove, one layer up: a caller that observed
    /// the exit and then stopped us would signal whatever the kernel handed that number to next.
    pub fn stop(&mut self) {
        let _ = self.child.request_stop();
        let deadline = Instant::now() + self.stop_grace;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(POLL),
                Err(_) => break,
            }
        }
        // Grace expired: hard-kill the whole supervisor tree, not just the root child.
        let _ = self.child.kill_tree();
        let _ = self.child.wait();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A supervisor stand-in that catches the graceful stop and exits on it.
    fn graceful_binary(name: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("guardian-stop-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("supervisor");
        std::fs::write(&path, "#!/bin/sh\ntrap 'exit 7' TERM\nsleep 60 &\nwait\n").unwrap();
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn stop_asks_gracefully_before_the_grace_expires() {
        // The graceful request goes through `ContainedChild`, the same reap-aware abstraction as
        // the hard kill, so no raw PID is ever signalled from here. If it were lost, this would
        // fall through to the grace expiry and hard-kill instead.
        let binary = graceful_binary("graceful");
        let dir = binary.parent().unwrap();
        let mut sup = Supervisor::launch(
            &binary,
            &dir.join("config.toml"),
            dir,
            None,
            Duration::from_secs(30),
        )
        .unwrap();
        let started = Instant::now();
        sup.stop();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "stop waited out the grace instead of asking the supervisor to exit"
        );
        assert!(sup.exited());
    }

    #[test]
    fn stopping_an_already_reaped_supervisor_signals_nothing() {
        // Once `exited()` has reaped the leader its PID is the kernel's to reassign; a stop after
        // that must be a no-op, not a signal aimed at whatever now holds that number.
        let binary = graceful_binary("reaped");
        let dir = binary.parent().unwrap();
        let mut sup = Supervisor::launch(
            &binary,
            &dir.join("config.toml"),
            dir,
            None,
            Duration::from_secs(30),
        )
        .unwrap();
        sup.stop();
        assert!(sup.exited());
        let started = Instant::now();
        sup.stop();
        assert!(started.elapsed() < Duration::from_secs(5));
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

    /// Whether the peer exits within `grace`.
    ///
    /// A failed read and the peer's exit are one event seen through two different pieces of
    /// kernel bookkeeping: the socket reports EOF as soon as the process's descriptors close,
    /// while the exit is not reapable — and so not visible to [`exited`](Self::exited) — until a
    /// moment later. Sampling `exited` once at the instant of a read failure therefore loses that
    /// race on the ordinary path and reports a supervisor that simply exited as a channel fault.
    ///
    /// Waiting a bounded moment makes the distinction decidable rather than timing-dependent: a
    /// peer whose descriptors closed because it is exiting has been reaped by the time `grace` is
    /// up, and one still running after it is a genuine channel fault. Only ever spent on a peer
    /// that is already finished with this channel, so the healthy path never pays it.
    fn exited_within(&mut self, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        loop {
            if self.exited() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(POLL);
        }
    }
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
