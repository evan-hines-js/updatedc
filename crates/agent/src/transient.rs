//! Distinguishing a node-local transient — a busy disk, a lock another process holds — from a
//! real failure, and retrying within a bounded budget instead of failing the cycle.

use crate::*;

/// End this agent because it cannot make progress, leaving every piece of durable evidence
/// (the transaction journal, the unspent marker claims, the rejection records) exactly as it is.
///
/// This is the ONLY response to an unrecoverable boot or update step, and it is deliberately an
/// exit rather than a wait: the agent is disposable — it holds no workload — and the launcher
/// relaunches it, so the next boot re-derives the identical, idempotent recovery from the same
/// evidence. Holding the process alive instead means a single failed durable write pins the node
/// down forever: no exit, so no relaunch, so no next boot, so the recovery that was supposed to
/// happen "next boot" never did. Replaying an operator hook in
/// a tight loop is not the alternative hazard it looks like either: the launcher throttles every
/// relaunch through one exponential backoff capped at five minutes, and that backoff is rate-
/// limited precisely so THIS path cannot escape it. An exit from here typically comes after a long
/// boot — situation gathering, activation, an operator hook with an operator-chosen timeout — so
/// the launcher's "it ran a while, this was a transient crash" reset would otherwise
/// fire on every cycle; it stops resetting past a bounded number of relaunches per hour, and the
/// loop settles at one replay per five minutes.
pub(crate) fn exit_for_relaunch(
    what: &str,
    cause: &dyn std::fmt::Display,
) -> Box<dyn std::error::Error> {
    let reason = format!(
        "{what} failed: {cause}; exiting with the recovery journal intact so the launcher \
         relaunches boot recovery"
    );
    error(&reason);
    reason.into()
}

/// How long a boot-recovery step is retried when what failed it is a node-local transient.
///
/// It must outlast the launcher's readiness gate plus its confirmation window (45s + 30s with the
/// shipped defaults), because that is the whole point: a candidate that spends the transient behind
/// its readiness signal gets COMMITTED, so if the fault outlives the budget the exit that follows
/// is an ordinary relaunch instead of a permanent, by-content-hash rejection.
pub(crate) const TRANSIENT_RETRY_BUDGET: Duration = Duration::from_secs(120);

/// How long a boot-recovery step waits between attempts at a node-local transient.
pub(crate) const TRANSIENT_RETRY_INTERVAL: Duration = Duration::from_secs(3);

/// Run one fallible boot-recovery step, waiting out node-local transients from behind the
/// readiness signal, and turning anything else into [`exit_for_relaunch`].
///
/// Boot recovery runs in front of the readiness signal because commitment is meant to attest that
/// these agent bytes reconciled their durable state. But for a CANDIDATE agent, exiting
/// before that signal is not the relaunch `exit_for_relaunch` describes — the launcher records the
/// candidate rejected, the predecessor comes back and blacklists the candidate's SHA-256 in
/// `agent-rejected`, a record that never expires. A full state volume, a read-only remount, an
/// EIO, or a CDN blip during staging would therefore strand this node an agent release behind
/// the fleet, permanently, over a fault that says nothing about the release — the same fault
/// attribution `update.rs` already makes for a pointer write and `self_update.rs` for a failed
/// handoff.
///
/// So a transient cause is retried instead, and readiness is signalled before the first retry:
/// with the signal sent, the confirmation window runs on its own clock and the candidate is
/// committed on the strength of what it is — bytes that started and stayed up — rather than on
/// whether this node's disk was writable at that moment. Retrying is safe because the step is
/// exactly what the next boot would re-derive: every phase is guarded by `recovery_pending`, so a
/// re-run resumes where the failure landed.
///
/// The retry is BOUNDED. An agent that never exits is the failure mode `exit_for_relaunch`
/// exists to prevent, so once the budget is spent this ends the process like any other
/// unrecoverable step — by then the candidate is committed, and the relaunch is throttled by the
/// launcher's backoff.
pub(crate) async fn recover_through_transients<T>(
    what: &str,
    launcher: &mut Launcher,
    shutdown: &AtomicBool,
    mut step: impl FnMut() -> io::Result<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + TRANSIENT_RETRY_BUDGET;
    loop {
        let error = match step() {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !retry_after_transient(&error, Instant::now(), deadline, shutdown) {
            return Err(exit_for_relaunch(what, &error));
        }
        warn(&format!(
            "{what} hit a node-local fault ({error}); signalling readiness and retrying in {}ms so \
             a transient cannot get these agent bytes rejected by content hash",
            TRANSIENT_RETRY_INTERVAL.as_millis()
        ));
        // Idempotent: the ordinary signal below this in `run` still happens, and only one READY
        // frame reaches the launcher.
        launcher.signal_ready();
        if sleep_interruptible(TRANSIENT_RETRY_INTERVAL, shutdown).await {
            return Err(exit_for_relaunch(what, &error));
        }
    }
}

/// Whether a failed recovery step earns another attempt from behind the readiness signal: only a
/// node-local transient, only while the budget lasts, and never once a stop was requested. Anything
/// else is the release's own fault (or out of time) and takes the [`exit_for_relaunch`] path.
pub(crate) fn retry_after_transient(
    error: &io::Error,
    now: Instant,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> bool {
    is_node_local_transient(error) && now < deadline && !shutdown.load(Ordering::SeqCst)
}

/// Whether an I/O failure is a fault of the NODE — its disk, its filesystem, its network — rather
/// than of the release or the state being reconciled. These are the causes that clear on their own
/// and say nothing about the bytes that hit them; every other kind (corrupt data, a bad path, an
/// invalid transition) is owned by whatever produced it.
pub(crate) fn is_node_local_transient(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::StorageFull
            | io::ErrorKind::QuotaExceeded
            | io::ErrorKind::ReadOnlyFilesystem
            | io::ErrorKind::ResourceBusy
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotConnected
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    ) {
        return true;
    }
    if io_error_chain_contains(
        error,
        foundation::durable::is_transient_filesystem_contention,
    ) {
        return true;
    }
    // Some OS faults have no portable `ErrorKind`, so recognise their raw codes. A post-commit
    // durability failure may wrap the original `io::Error`; inspect the complete source chain so
    // the retry decision is identical before and after the durable-write boundary adds context.
    #[cfg(unix)]
    {
        has_raw_os_error(error, &[libc::EIO])
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn has_raw_os_error(error: &io::Error, codes: &[i32]) -> bool {
    io_error_chain_contains(error, |cause| {
        cause
            .raw_os_error()
            .is_some_and(|code| codes.contains(&code))
    })
}

fn io_error_chain_contains(error: &io::Error, predicate: impl Fn(&io::Error) -> bool) -> bool {
    if predicate(error) {
        return true;
    }
    let mut current = error
        .get_ref()
        .map(|cause| cause as &(dyn std::error::Error + 'static));
    while let Some(cause) = current {
        if cause.downcast_ref::<io::Error>().is_some_and(&predicate) {
            return true;
        }
        current = cause.source();
    }
    false
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    #[test]
    fn filesystem_contention_policy_survives_durability_wrapping() {
        // The real exclusive-handle test returns ACCESS_DENIED on the Actions filesystem. Prove
        // that agent recovery delegates that result to foundation's shared contention policy even
        // after the durable boundary adds an io::Error source layer.
        let direct = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        assert!(is_node_local_transient(&direct));

        let wrapped = io::Error::other(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32));
        assert!(is_node_local_transient(&wrapped));
    }
}
