//! Distinguishing a node-local transient — a busy disk, a lock another process holds — from a
//! real failure, and retrying within a bounded budget instead of failing the cycle.

use crate::*;

/// End this agent because it cannot make progress, leaving every piece of durable transaction
/// evidence exactly as it is.
///
/// This is the ONLY response to an unrecoverable boot or update step, and it is deliberately an
/// exit rather than a wait: the agent is disposable — it holds no workload — and its platform
/// service manager relaunches it, so the next boot re-derives identical recovery from the same
/// evidence. Holding the process alive instead means a single failed durable write pins the node
/// down forever: no exit, so no relaunch, so no next boot, so the recovery that was supposed to
/// happen "next boot" never did. Replaying an operator hook in
/// a tight loop is bounded by the platform service's restart policy.
pub(crate) fn exit_for_relaunch(
    what: &str,
    cause: &dyn std::fmt::Display,
) -> Box<dyn std::error::Error> {
    let reason = format!(
        "{what} failed: {cause}; exiting with the recovery journal intact so the service manager \
         relaunches boot recovery"
    );
    error(&reason);
    reason.into()
}

/// How long a boot-recovery step is retried when what failed it is a node-local transient.
///
/// It is long enough to absorb short-lived node faults without forcing a service restart.
pub(crate) const TRANSIENT_RETRY_BUDGET: Duration = Duration::from_secs(120);

/// How long a boot-recovery step waits between attempts at a node-local transient.
pub(crate) const TRANSIENT_RETRY_INTERVAL: Duration = Duration::from_secs(3);

/// Run one fallible boot-recovery step, waiting out node-local transients and turning anything
/// else into [`exit_for_relaunch`]. Retrying is safe because every phase is guarded by
/// `recovery_pending`, so a re-run resumes where the failure landed. The retry remains bounded;
/// once the budget is spent the platform service manager gets a clean restart boundary.
pub(crate) async fn recover_through_transients<T>(
    what: &str,
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
            "{what} hit a node-local fault ({error}); retrying in {}ms",
            TRANSIENT_RETRY_INTERVAL.as_millis()
        ));
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
