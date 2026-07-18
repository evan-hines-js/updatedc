//! The guardian's operating-system surface, behind one seam.
//!
//! The guardian's own code is platform-agnostic; every OS-specific call it makes — the
//! contained application process, the inherited control-channel socketpair/pipes, polling
//! — lives in a per-platform adapter here. Its only dependencies are the platform binding
//! crates (`libc`, `windows-sys`), which are compile-time ABI bindings, not behavioral
//! runtime dependencies, plus the frozen `control` protocol. Keeping the OS surface in one
//! place is what lets the rest of the guardian read the same on every target.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// The contained application process — the guardian's one port to a running child. The
/// per-platform adapters (`unix`/`windows`) implement it over their native containment
/// (process group + `PR_SET_PDEATHSIG` on Unix, a kill-on-close Job Object on Windows);
/// [`spawn`] is the factory. Expressing it as a trait keeps the two adapters honest — they
/// must satisfy the same contract — and lets a fake drive [`App`](crate::app::App) in tests
/// without spawning a real process.
pub trait Process: Send {
    fn pid(&self) -> u32;
    /// The exit code if the process has exited (cached, so it is safe to poll repeatedly);
    /// `None` while it is still running.
    fn poll_exit(&mut self) -> Option<i32>;
    /// Stop the process and everything it spawned (a graceful signal, then a hard kill
    /// after `grace`).
    fn stop(&mut self, grace: Duration);
}

/// Set by the platform stop-signal handler (SIGTERM/SIGINT on Unix, a console close event
/// on Windows). The guardian polls it to shut down cleanly on either target.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Whether the init system has asked the guardian to stop.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Called from the platform signal handler; async-signal-safe (a single atomic store).
fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}
