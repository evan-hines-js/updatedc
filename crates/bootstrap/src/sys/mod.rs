//! The launcher's operating-system surface, behind one seam.
//!
//! The launcher's own code is platform-agnostic; every OS-specific call it makes — the
//! inherited control-channel socketpair/pipes, polling, the stop signal — lives in a
//! per-platform adapter here. Its only dependencies are the platform binding crates
//! (`libc`, `windows-sys`), which are compile-time ABI bindings, not behavioral runtime
//! dependencies, plus the frozen `control` protocol. Keeping the OS surface in one place
//! is what lets the rest of the launcher read the same on every target.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// Set by the platform stop-signal handler (SIGTERM/SIGINT on Unix, a console close event
/// on Windows). The launcher polls it to shut down cleanly on either target.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Whether the init system has asked the launcher to stop.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Called from the platform signal handler; async-signal-safe (a single atomic store).
fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}
