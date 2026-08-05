//! The supervisor's client for the guardian control channel.
//!
//! The guardian — not the supervisor — owns the application. So the supervisor never
//! spawns, adopts, signals, or reaps it directly: it asks the guardian to, over the
//! inherited control channel the guardian handed it at launch. This module is the thin
//! consumer side of the frozen [`control`] protocol; the guardian is the server.
//!
//! Each operation is one synchronous request/response exchange. The guardian speaks
//! first with a [`Hello`], which [`Guardian::connect`] reads and negotiates before any
//! request; from then on every read is the response to the supervisor's last request.

use std::path::Path;

use control::{
    Capabilities, CommandSpec, Hello, Nonce, Request, Response, CONTROL_ENV, READY_NONCE_ENV,
};

/// The protocol majors this supervisor build can speak.
const SUPPORTED_MAJORS: &[u16] = &[control::PROTOCOL_MAJOR];

/// A connection to the guardian, plus the negotiated capabilities and this launch's
/// readiness nonce.
pub(crate) struct Guardian {
    conn: Conn,
    caps: Capabilities,
    ready_nonce: Nonce,
    /// The application the guardian is running, as this connection knows it: seeded from the
    /// launch environment (a supervisor crash-relaunch or a candidate activation hands the live
    /// PID across exec) and kept true by every stop and launch that goes through here. This is the
    /// supervisor's ONE record of it — [`crate::app::App::pid`] reads it rather than keeping a
    /// second copy that the two modes' launch paths would drift apart.
    ///
    /// The environment variable is fixed at exec time and can only ever be *stale*, so it is read
    /// exactly once, here. A boot that stops the application before planning — repairing a
    /// committed bundle that failed local verification — would otherwise still be told one is
    /// running, and the planner would adopt a PID that no longer exists instead of launching, so
    /// the boot health gate would probe an application that does not exist.
    app_pid: Option<u32>,
    /// Whether this launch has already sent `READY`. See [`Guardian::signal_ready`].
    ready_signalled: bool,
}

impl Guardian {
    /// Connect over the inherited channel and complete the handshake. Fails if the
    /// guardian did not launch this supervisor (no channel) or the protocols do not
    /// share a major.
    pub(crate) fn connect() -> Result<Guardian, String> {
        let ready_nonce = read_ready_nonce()?;
        let mut conn = Conn::inherit()?;
        let hello =
            Hello::read(conn.reader()).map_err(|e| format!("reading guardian hello: {e}"))?;
        let caps = hello.negotiate(SUPPORTED_MAJORS).ok_or_else(|| {
            format!(
                "no shared control-protocol major (guardian offers {:?}, supervisor speaks {:?})",
                hello.majors, SUPPORTED_MAJORS
            )
        })?;
        Ok(Guardian {
            conn,
            caps,
            ready_nonce,
            app_pid: adopted_app_pid(),
            ready_signalled: false,
        })
    }

    /// The application the guardian is running right now, if any — what the boot planner adopts
    /// instead of launching a duplicate.
    pub(crate) fn running_app(&self) -> Option<u32> {
        self.app_pid
    }

    /// A connection in the shape [`Guardian::connect`] produces when the guardian handed a live
    /// application across exec, over a socketpair whose other end the test drives.
    #[cfg(all(test, unix))]
    pub(crate) fn for_test(
        stream: std::os::unix::net::UnixStream,
        app_pid: Option<u32>,
    ) -> Guardian {
        Guardian {
            conn: Conn { stream },
            caps: Hello::current()
                .negotiate(SUPPORTED_MAJORS)
                .expect("this build negotiates with itself"),
            ready_nonce: [0u8; 16],
            app_pid,
            ready_signalled: false,
        }
    }

    /// Refuse to use an operation the guardian did not advertise. For today's single
    /// protocol major this is always satisfied, but it is what lets a newer supervisor
    /// run under an older guardian: it detects a missing capability instead of hanging
    /// on a request the guardian will never answer.
    fn require(&self, capability: u16, what: &str) -> Result<(), String> {
        if self.caps.supports(capability) {
            Ok(())
        } else {
            Err(format!("the guardian does not support {what}"))
        }
    }

    fn exchange(&mut self, req: &Request) -> Result<Response, GuardianError> {
        // A write/read failure on the channel is a transport failure, not a refusal: the
        // guardian died, the pipe broke, or a frame was truncated. Tag it `Channel` so the
        // update path recovers rather than blaming the candidate.
        req.write(self.conn.writer())
            .map_err(|e| GuardianError::Channel(format!("sending control request: {e}")))?;
        Response::read(self.conn.reader())
            .map_err(|e| GuardianError::Channel(format!("reading control response: {e}")))
    }

    /// Ask the guardian to launch the application from `spec`. Returns the application's
    /// PID. A `Channel` error means the control channel failed (e.g. a SIGKILLed guardian);
    /// a `Refused` error means the guardian answered but the launch itself failed.
    pub(crate) fn launch(&mut self, spec: &CommandSpec) -> Result<u32, GuardianError> {
        self.require(control::CAP_LAUNCH_APP_V1, "LAUNCH")
            .map_err(GuardianError::Refused)?;
        match self.exchange(&Request::Launch(spec.clone()))? {
            Response::Launched { pid } => {
                self.app_pid = Some(pid);
                Ok(pid)
            }
            Response::Error(msg) => Err(GuardianError::Refused(format!(
                "guardian could not launch the application: {msg}"
            ))),
            other => Err(GuardianError::Refused(format!(
                "unexpected reply to LAUNCH: {other:?}"
            ))),
        }
    }

    /// Stop the application (the guardian escalates to a hard kill). Used to quiesce it
    /// before activating a release during an update.
    ///
    /// The PID is forgotten as soon as the stop is asked for, whether or not the answer arrives.
    /// Relaunching cannot duplicate an application — `bootstrap::app::App::launch` stops whatever
    /// it is running before it spawns — so the only hazard left is the other direction: *adopting*
    /// a process this supervisor asked to have stopped. That PID may be gone (the health gate then
    /// probes an application that does not exist), or still be running the very bytes a repair
    /// just replaced, with `active == installed` afterwards so drift enforcement never corrects it.
    pub(crate) fn stop(&mut self) -> Result<(), String> {
        self.require(control::CAP_STOP_APP, "STOP")?;
        self.app_pid = None;
        self.expect_ok(&Request::Stop, "STOP")
    }

    /// Publish the application traffic state exposed by the guardian's stable probe
    /// endpoint. False is sent before drain; true only after health verification.
    pub(crate) fn traffic_ready(&mut self, ready: bool) -> Result<(), String> {
        self.require(control::CAP_TRAFFIC_STATE, "TRAFFIC_STATE")?;
        self.expect_ok(&Request::TrafficReady(ready), "TRAFFIC_STATE")
    }

    pub(crate) fn application_failed(&mut self) -> Result<(), String> {
        self.require(control::CAP_FAIL_APPLICATION, "FAIL_APPLICATION")?;
        self.expect_ok(&Request::ApplicationFailed, "FAIL_APPLICATION")
    }

    /// Hand off to a staged replacement supervisor at `path`; the guardian relaunches
    /// from it under a readiness gate after this supervisor exits.
    pub(crate) fn replace_supervisor(&mut self, path: &Path) -> Result<(), String> {
        self.require(control::CAP_REPLACE_SUPERVISOR_V1, "REPLACE_SUPERVISOR")?;
        self.expect_ok(
            &Request::ReplaceSupervisor(path.as_os_str().to_os_string()),
            "REPLACE_SUPERVISOR",
        )
    }

    /// Prove this supervisor launch reached readiness (commits a candidate handoff), and hand back
    /// the proof that it was sent.
    ///
    /// A guardian that will not take the signal is warned about rather than fatal: this supervisor
    /// is already running and there is nothing better to do about it. The token is returned either
    /// way, because it records the *ordering* — that this call has happened — which is what the
    /// waits behind it depend on.
    ///
    /// At most one `READY` reaches the guardian per launch. Boot recovery signals readiness as
    /// soon as it starts waiting out a node-local transient (see `run`), and the boot path then
    /// signals again at its ordinary point; a second frame on the wire would be answered — the
    /// guardian's dispatch ignores it once the nonce is spent — but the supervisor would be
    /// blocked on that exchange for no reason, so the send is made once here instead.
    pub(crate) fn signal_ready(&mut self) -> ReadySignalled {
        if self.ready_signalled {
            return ReadySignalled(());
        }
        self.ready_signalled = true;
        let sent = match self.require(control::CAP_READY, "READY") {
            Ok(()) => self.expect_ok(&Request::Ready(self.ready_nonce), "READY"),
            Err(unsupported) => Err(unsupported),
        };
        if let Err(error) = sent {
            crate::warn(&format!(
                "could not signal readiness to the guardian: {error}"
            ));
        }
        ReadySignalled(())
    }

    fn expect_ok(&mut self, req: &Request, what: &str) -> Result<(), String> {
        match self.exchange(req).map_err(|e| e.to_string())? {
            Response::Ok => Ok(()),
            Response::Error(msg) => Err(format!("guardian rejected {what}: {msg}")),
            other => Err(format!("unexpected reply to {what}: {other:?}")),
        }
    }
}

/// Proof that this boot has already told the guardian the supervisor is ready. Only
/// [`Guardian::signal_ready`] can make one — the field is private to this module — so a wait that
/// demands one cannot be moved back in front of the readiness signal without failing to compile.
///
/// [`crate::secrets::SecretManager::acquire`] is that wait: in front of the signal, an unreachable
/// secrets endpoint is indistinguishable from a supervisor binary that cannot start, and the
/// candidate's bytes are then rejected by content hash, permanently.
pub(crate) struct ReadySignalled(());

#[cfg(test)]
impl ReadySignalled {
    /// Stand in for the guardian handshake, for tests of the waits that sit behind it.
    pub(crate) fn for_test() -> ReadySignalled {
        ReadySignalled(())
    }
}

/// Why a guardian request failed, distinguished by fault attribution. `Refused` is a real
/// operation failure the managed candidate owns (a bad launch spec, a missing capability, an
/// unexpected reply). `Channel` is a control-channel transport failure — a SIGKILLed guardian,
/// a broken pipe, a closed or malformed frame — which is NEVER the candidate's fault. It maps to
/// `io::ErrorKind::ConnectionReset` so the update path can let it drive boot recovery (which
/// retries) instead of permanently rejecting a healthy release.
pub(crate) enum GuardianError {
    Channel(String),
    Refused(String),
}

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::Channel(message) | GuardianError::Refused(message) => {
                f.write_str(message)
            }
        }
    }
}

impl From<GuardianError> for std::io::Error {
    fn from(error: GuardianError) -> Self {
        match error {
            GuardianError::Channel(message) => {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, message)
            }
            GuardianError::Refused(message) => std::io::Error::other(message),
        }
    }
}

/// The application PID the guardian handed this supervisor across exec, if any (a supervisor
/// crash-relaunch or candidate activation). Read once, into [`Guardian::app_pid`], which is the
/// supervisor's only answer to "is an application running" from then on.
fn adopted_app_pid() -> Option<u32> {
    std::env::var(control::APP_PID_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
}

/// The guardian's state directory, from the launch environment.
pub(crate) fn state_dir() -> Option<std::path::PathBuf> {
    std::env::var(control::STATE_DIR_ENV)
        .ok()
        .map(std::path::PathBuf::from)
}

/// One marker file the guardian writes for the supervisor: evidence about the launch that just
/// ended, which the supervisor turns into a rollback or a rejection.
///
/// A marker is only ever obtained as a [`Claim`] — a specific *instance* of the file, pinned to
/// the bytes that were read — and a claim is the only thing that can erase one. Three hazards are
/// unrepresentable as a result:
///
/// * Consuming evidence by reading it. A crash or ENOSPC between the unlink and the durable write
///   the marker implies would erase the only record that the application died inside its
///   confirmation window, and the next boot would confirm the bad update instead of reverting it.
///   Re-deriving evidence after a crash is idempotent; re-creating deleted evidence is impossible.
/// * Erasing evidence nobody read. Boot reconciliation runs while the guardian still owns the live
///   application, so the guardian can write a *fresh* marker at any point during it. Clearing "the
///   marker file" would silently swallow that one; clearing a claim touches only the instance
///   whose contents drove this boot's decisions, and leaves a newer instance for the next boot.
/// * Being wedged by garbage. A marker whose bytes are not evidence — a truncated write from
///   outside this tower, an operator's stray `echo`, a directory at the path — is DISCARDED with a
///   warning rather than failing the boot: failing would repeat identically on every subsequent
///   boot, and a node must never be permanently unbootable because of a corrupt marker file.
struct Marker {
    path: std::path::PathBuf,
}

/// A marker instance that has been read, pinned to the exact bytes it held. Holding one is the
/// proof of reading that [`Claim::clear`] requires; consuming one is what makes clearing happen at
/// most once, for at most that instance.
///
/// The *contents* are the instance identity, and nothing else: the guardian writes markers through
/// `foundation::durable::atomic_write_managed`, but filesystem metadata cannot tell two writes
/// apart portably (on Windows NTFS tunneling restores the creation time across the temp+rename,
/// modification time has ~15 ms granularity, and the length of a fixed-shape marker never varies).
/// So each marker's content is made self-identifying at the writer instead: the service-exit marker
/// carries a fresh per-exit stamp, and the rejected-supervisor marker carries the candidate's path
/// — which is precisely the evidence, so two instances with identical bytes say the same thing and
/// have the same durable consequence.
pub(crate) struct Claim {
    path: std::path::PathBuf,
    content: String,
}

/// Where [`Claim::clear`] parks the one instance it took off the marker path. A fixed sibling name,
/// not a fresh one per call: a single supervisor owns this state directory (the instance lock), so
/// there is never a second clear in flight, and a fixed name is what makes an interrupted clear
/// recoverable by [`recover_interrupted_clear`] rather than leaving orphans nothing will ever find.
fn taken_path(marker: &Path) -> std::path::PathBuf {
    updated::config::with_suffix(marker, ".clearing")
}

/// Put an instance back on the marker path. Only ever used for one that this boot took but must
/// NOT consume — a newer instance, or one whose clear was interrupted. If a marker has landed on
/// the path in the meantime it is newer evidence of the same event and wins; what must never
/// happen is ending with no marker at all when one is owed.
fn restore_taken(taken: &Path, marker: &Path) {
    let restored = if marker.exists() {
        foundation::durable::remove_file(taken)
    } else {
        std::fs::rename(taken, marker)
    };
    if let Err(error) = restored {
        crate::warn(&format!(
            "could not restore the guardian marker {}: {error}",
            marker.display()
        ));
    }
}

/// A clear that died between taking the marker and deciding its fate left the instance it took
/// beside the marker path. Restore it before reading, so that one-rename window cannot swallow a
/// marker whose consequence had not committed. Runs on every claim, which is the only place a
/// marker is ever read.
fn recover_interrupted_clear(marker: &Path) {
    let taken = taken_path(marker);
    if taken.exists() {
        restore_taken(&taken, marker);
    }
}

fn warn_unusable(path: &Path, why: &str) {
    crate::warn(&format!(
        "guardian marker {} {why}; discarding it — it carries no evidence",
        path.display()
    ));
}

/// Report that whatever is at `path` cannot be evidence at all — a directory, a symlink, bytes
/// that are not text — and get rid of it, so the same garbage cannot fail every future boot.
/// Always best-effort: if the removal fails the node still boots, having simply learned nothing.
///
/// The removal is `remove_path`, not `remove_file`, precisely because the garbage may be a
/// *directory*: unlinking one fails on every platform, so a file-only removal would leave the
/// directory in place and repeat this same warning pair on every boot for the life of the node.
fn discard(path: &Path, why: &str) -> Option<Claim> {
    warn_unusable(path, why);
    if let Err(error) = foundation::durable::remove_path(path) {
        crate::warn(&format!(
            "could not remove the unusable guardian marker {}: {error}",
            path.display()
        ));
    }
    None
}

impl Marker {
    /// The managed service exited spontaneously. Any exit, including zero, invalidates an
    /// unconfirmed release and requires boot reconciliation.
    fn service_exit(state_dir: &Path) -> Marker {
        Marker {
            path: state_dir.join(control::SERVICE_EXITED_MARKER_FILE),
        }
    }

    /// A candidate supervisor failed its readiness gate; its staged path is the marker's content,
    /// and this supervisor records the rejection so the candidate is never staged again.
    fn rejected_supervisor(state_dir: &Path) -> Marker {
        Marker {
            path: state_dir.join(control::REJECTED_SUPERVISOR_FILE),
        }
    }

    /// Claim the marker as it is right now, without disturbing it. A genuine I/O failure (EIO, a
    /// permission problem) is propagated — the environment is broken, not the file — while
    /// anything at the path that cannot *be* evidence is discarded and read as "no marker".
    fn claim(self) -> std::io::Result<Option<Claim>> {
        recover_interrupted_clear(&self.path);
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !metadata.file_type().is_file() {
            return Ok(discard(&self.path, "is not a regular file"));
        }
        match std::fs::read_to_string(&self.path) {
            Ok(content) => Ok(Some(Claim {
                path: self.path,
                content,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                Ok(discard(&self.path, "is not valid UTF-8"))
            }
            Err(e) => Err(e),
        }
    }
}

impl Claim {
    /// The claim's single line of content, for a marker that carries a value. `None` for a marker
    /// of any other shape: it is corrupt, so it is not interpreted.
    fn single_line(&self) -> Option<&str> {
        let trimmed = self.content.trim();
        if trimmed.is_empty() || self.content.lines().count() != 1 {
            return None;
        }
        Some(trimmed)
    }

    /// Erase exactly the instance that was claimed. Call only AFTER the durable consequence
    /// derived from it — a synthesized rollback journal, a recorded rejection — has been
    /// committed; the claim is consumed, so it cannot be cleared twice.
    ///
    /// If the bytes on disk are no longer the ones that were read, the guardian wrote a new marker
    /// while this boot was reconciling: that instance's evidence has been read by nobody, so it
    /// is left for the next boot.
    /// The instance is taken off the marker path in ONE atomic step (a rename) before its bytes are
    /// compared, so this call can only ever destroy the instance it took. Comparing in place and
    /// then unlinking the *path* — the shape this replaced — left a window between the two calls:
    /// the guardian owns the live application throughout boot reconciliation, and a marker it
    /// renamed into place inside that window was unlinked with its evidence read by nobody, which
    /// is precisely how a service exit gets lost and a crashed candidate confirmed.
    fn clear(self) -> std::io::Result<()> {
        let taken = taken_path(&self.path);
        match std::fs::rename(&self.path, &taken) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
        let mine = match std::fs::read_to_string(&taken) {
            Ok(content) => content == self.content,
            // Bytes that are no longer text at all are a different instance than the one read.
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                restore_taken(&taken, &self.path);
                return Err(e);
            }
        };
        if mine {
            return foundation::durable::remove_file(&taken);
        }
        crate::log(&format!(
            "guardian marker {} was rewritten during boot reconciliation; leaving the new one \
             for the next boot",
            self.path.display()
        ));
        restore_taken(&taken, &self.path);
        Ok(())
    }

    /// Throw away a marker whose content is not evidence, without touching a newer instance that
    /// landed mid-boot (the same rule [`Claim::clear`] follows). Best-effort: a failure to remove
    /// it only means the warning repeats next boot, which is the point — it must never stop one.
    fn discard_corrupt(self, why: &str) {
        warn_unusable(&self.path, why);
        if let Err(error) = self.clear() {
            crate::warn(&format!(
                "could not remove the unusable guardian marker: {error}"
            ));
        }
    }
}

/// Everything the guardian left behind for this boot, read once, up front, and cleared one claim
/// at a time as each implied intent becomes durable.
///
/// There is no way to reach a marker except through here, and no way to clear one except by
/// surrendering the claim that read it — so "cleared a marker whose consequence never committed"
/// and "cleared a marker nobody read" are both off the table by construction rather than by call
/// ordering.
pub(crate) struct Evidence {
    service_exit: Option<Claim>,
    rejected_supervisor: Option<(Claim, std::path::PathBuf)>,
}

impl Evidence {
    /// Read both markers. `state_dir` is `None` when this supervisor was not launched by a
    /// guardian, in which case there is never any evidence.
    pub(crate) fn read(state_dir: Option<&Path>) -> std::io::Result<Evidence> {
        let Some(state_dir) = state_dir else {
            return Ok(Evidence {
                service_exit: None,
                rejected_supervisor: None,
            });
        };
        let rejected_supervisor = match Marker::rejected_supervisor(state_dir).claim()? {
            Some(claim) => {
                let candidate = claim.single_line().map(std::path::PathBuf::from);
                match candidate {
                    Some(path) => Some((claim, path)),
                    // A rejected-supervisor marker that does not name exactly one candidate path
                    // cannot reject anything. Discarding it costs at most one re-staging of a
                    // candidate the guardian will reject again (and record again, legibly);
                    // failing the boot on it would fail every boot after it, forever.
                    None => {
                        claim.discard_corrupt("does not name exactly one candidate path");
                        None
                    }
                }
            }
            None => None,
        };
        Ok(Evidence {
            service_exit: Marker::service_exit(state_dir).claim()?,
            rejected_supervisor,
        })
    }

    /// Whether the managed service exited spontaneously under the previous supervisor.
    pub(crate) fn service_exited(&self) -> bool {
        self.service_exit.is_some()
    }

    /// The staged path of a candidate supervisor the guardian rejected at its readiness gate.
    pub(crate) fn rejected_supervisor(&self) -> Option<&Path> {
        self.rejected_supervisor
            .as_ref()
            .map(|(_, path)| path.as_path())
    }

    /// Drop the service-exit evidence, now that the rollback or rejection it implied is durable.
    pub(crate) fn clear_service_exit(&mut self) -> std::io::Result<()> {
        match self.service_exit.take() {
            Some(claim) => claim.clear(),
            None => Ok(()),
        }
    }

    /// Drop the rejected-supervisor evidence, now that the candidate's hash is durably rejected.
    pub(crate) fn clear_rejected_supervisor(&mut self) -> std::io::Result<()> {
        match self.rejected_supervisor.take() {
            Some((claim, _)) => claim.clear(),
            None => Ok(()),
        }
    }
}

fn read_ready_nonce() -> Result<Nonce, String> {
    let hex = std::env::var(READY_NONCE_ENV).map_err(|_| {
        format!("{READY_NONCE_ENV} not set; the supervisor must be launched by the guardian")
    })?;
    parse_nonce(&hex).ok_or_else(|| format!("{READY_NONCE_ENV} is not 32 hex digits"))
}

fn parse_nonce(hex: &str) -> Option<Nonce> {
    if hex.len() != 32 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *b = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

// ── the inherited channel endpoint ───────────────────────────────────────────────

#[cfg(unix)]
struct Conn {
    stream: std::os::unix::net::UnixStream,
}

/// Mark `fd` close-on-exec, so it is not inherited by anything this process launches.
#[cfg(unix)]
fn set_cloexec(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
impl Conn {
    fn inherit() -> Result<Conn, String> {
        use std::os::fd::FromRawFd;
        let fd: std::os::fd::RawFd = std::env::var(CONTROL_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("{CONTROL_ENV} is not a valid descriptor"))?;
        // Safety: the guardian created this socketpair end and handed us its number
        // across exec; nothing else owns it.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        // The guardian cleared FD_CLOEXEC so this endpoint would survive *our* exec. Re-arm
        // it now that we own it, so it stops here: nothing we launch is a party to the
        // control protocol, and a descendant of the operator's lifecycle provider holding this
        // fd could drive the guardian directly — a single `Stop` frame would take the
        // application down with no crash recorded and nothing to relaunch it.
        set_cloexec(fd).map_err(|e| format!("securing the control channel endpoint: {e}"))?;
        Ok(Conn { stream })
    }

    fn reader(&mut self) -> &mut std::os::unix::net::UnixStream {
        &mut self.stream
    }

    fn writer(&mut self) -> &mut std::os::unix::net::UnixStream {
        &mut self.stream
    }
}

#[cfg(windows)]
struct Conn {
    reader: std::fs::File,
    writer: std::fs::File,
}

/// Clear `HANDLE_FLAG_INHERIT` on `handle`, so it is not inherited by anything this process
/// launches. The Windows counterpart of [`set_cloexec`]: `std`'s spawn always passes
/// `bInheritHandles = TRUE` with no attribute list, so this flag — which travels with the
/// handle across spawn — is the only thing that stops the channel here.
#[cfg(windows)]
fn clear_inherit(handle: std::os::windows::io::RawHandle) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    let ok = unsafe { SetHandleInformation(handle as _, HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
impl Conn {
    fn inherit() -> Result<Conn, String> {
        use std::os::windows::io::{FromRawHandle, RawHandle};
        let value = std::env::var(CONTROL_ENV).map_err(|_| format!("{CONTROL_ENV} not set"))?;
        let (r, w) = value
            .split_once(',')
            .ok_or_else(|| format!("{CONTROL_ENV} must be `read,write` handle values"))?;
        let r: usize = r
            .parse()
            .map_err(|_| format!("{CONTROL_ENV} read handle is not a number"))?;
        let w: usize = w
            .parse()
            .map_err(|_| format!("{CONTROL_ENV} write handle is not a number"))?;
        // Safety: the guardian created these anonymous-pipe ends and handed us their
        // inheritable handle values across spawn; nothing else owns them.
        let conn = Conn {
            reader: unsafe { std::fs::File::from_raw_handle(r as RawHandle) },
            writer: unsafe { std::fs::File::from_raw_handle(w as RawHandle) },
        };
        // The guardian marked these ends inheritable so they would survive *our* spawn. Clear
        // it now that we own them, so the channel stops here: nothing we launch is a party to
        // the control protocol, and a descendant of the operator's lifecycle provider holding
        // these handles could drive the guardian directly — a single `Stop` frame would take
        // the application down with no crash recorded and nothing to relaunch it. This is the
        // exact counterpart of the unix arm's FD_CLOEXEC re-arm; bootstrap cannot do it for us,
        // because the flag travels with the handle into this process.
        for handle in [r as RawHandle, w as RawHandle] {
            clear_inherit(handle)
                .map_err(|e| format!("securing the control channel endpoint: {e}"))?;
        }
        Ok(conn)
    }

    fn reader(&mut self) -> &mut std::fs::File {
        &mut self.reader
    }

    fn writer(&mut self) -> &mut std::fs::File {
        &mut self.writer
    }
}

/// Answer one request the way the guardian would, so the exchange under test completes. Shared
/// with [`crate::app`], whose provider-managed launch path is one such exchange.
#[cfg(all(test, unix))]
pub(crate) fn answering(
    mut peer: std::os::unix::net::UnixStream,
    response: Response,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        Request::read(&mut peer).expect("one request");
        response.write(&mut peer).expect("one response");
    })
}

/// The connection's own bookkeeping, driven over a real socketpair with a stand-in guardian
/// answering one request. Unix-only because the channel endpoint is: on Windows it is a pair of
/// anonymous pipe handles, and the state under test lives above that split.
#[cfg(all(test, unix))]
mod channel_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn an_acknowledged_stop_forgets_the_application_the_guardian_was_running() {
        // Regression: the answer to "is an application running" was the launch environment, fixed
        // at exec time and never updated. A boot that stopped the child to repair a committed
        // bundle that failed local verification therefore still saw it running, and the planner
        // adopted a PID that no longer existed — nothing was ever launched, and the boot health
        // gate probed an application that did not exist.
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let peer = answering(theirs, Response::Ok);
        let mut guardian = Guardian::for_test(ours, Some(4321));
        assert_eq!(guardian.running_app(), Some(4321));

        guardian.stop().expect("the guardian acknowledges STOP");

        assert_eq!(guardian.running_app(), None);
        peer.join().expect("the stand-in guardian");
    }

    #[test]
    fn an_unanswered_stop_forgets_the_application_too() {
        // The guardian answers STOP with Ok unconditionally, so the only stop that fails is one
        // whose channel died — a SIGKILLed guardian, a broken pipe. Keeping the PID through that
        // was justified as "otherwise we launch a second application", which the guardian makes
        // impossible (its `App::launch` stops whatever it is running first). What keeping it
        // actually bought was ADOPTING a process this boot asked to have stopped: dead, or alive
        // on the bytes a repair just replaced, and with active == installed nothing corrects it.
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        drop(theirs);
        let mut guardian = Guardian::for_test(ours, Some(4321));

        assert!(guardian.stop().is_err(), "the channel is gone");

        assert_eq!(guardian.running_app(), None);
    }

    #[test]
    fn a_launch_records_the_application_it_started() {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let peer = answering(theirs, Response::Launched { pid: 77 });
        let mut guardian = Guardian::for_test(ours, None);

        let spec = CommandSpec {
            program: "/bin/true".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
        };
        assert!(matches!(guardian.launch(&spec), Ok(77)));

        assert_eq!(guardian.running_app(), Some(77));
        peer.join().expect("the stand-in guardian");
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("supervisor-markers-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// Stand in for the guardian's writes (`bootstrap::record`): a self-identifying service-exit
    /// stamp — the exit code plus a per-exit nonce — and the candidate path.
    fn write_markers(state: &Path, candidate: &str) {
        static EXIT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stamp = format!(
            "1 {:032x}",
            EXIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        foundation::durable::atomic_write_managed(
            &state.join(control::SERVICE_EXITED_MARKER_FILE),
            ".guardian-",
            stamp.as_bytes(),
        )
        .unwrap();
        foundation::durable::atomic_write_managed(
            &state.join(control::REJECTED_SUPERVISOR_FILE),
            ".guardian-",
            candidate.as_bytes(),
        )
        .unwrap();
    }

    fn exists(state: &Path, file: &str) -> bool {
        state.join(file).exists()
    }

    #[test]
    fn a_marker_survives_until_its_claim_is_explicitly_cleared() {
        // Reading must NOT consume: the evidence has to outlive the boot's durable writes, so a
        // crash between them re-derives the same recovery rather than losing it.
        let state = dir("service-exit");
        write_markers(&state, "/state/supervisors/abc/supervisor");

        let mut evidence = Evidence::read(Some(&state)).unwrap();
        assert!(evidence.service_exited());
        assert_eq!(
            evidence.rejected_supervisor(),
            Some(Path::new("/state/supervisors/abc/supervisor"))
        );
        assert!(
            Evidence::read(Some(&state)).unwrap().service_exited(),
            "a re-read still sees the marker"
        );

        evidence.clear_service_exit().unwrap();
        evidence.clear_rejected_supervisor().unwrap();
        assert!(!exists(&state, control::SERVICE_EXITED_MARKER_FILE));
        assert!(!exists(&state, control::REJECTED_SUPERVISOR_FILE));
        // Consumed: a second clear is a no-op, not a second unlink of whatever is there now.
        evidence.clear_service_exit().unwrap();
        evidence.clear_rejected_supervisor().unwrap();
    }

    #[test]
    fn a_marker_written_during_reconciliation_is_never_cleared_unread() {
        // The guardian still owns the live application while the supervisor reconciles its boot,
        // so it can record a fresh spontaneous exit at any point in that window. Clearing must
        // erase only the instance this boot actually read; the new one is the next boot's
        // evidence, and losing it would let a crashed candidate be confirmed.
        let state = dir("rewritten");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let mut evidence = Evidence::read(Some(&state)).unwrap();

        // The guardian writes new markers mid-boot (a fresh file renamed into place).
        write_markers(&state, "/state/supervisors/def/supervisor");

        evidence.clear_service_exit().unwrap();
        evidence.clear_rejected_supervisor().unwrap();
        assert!(
            exists(&state, control::SERVICE_EXITED_MARKER_FILE),
            "the marker written during reconciliation must survive"
        );
        let next = Evidence::read(Some(&state)).unwrap();
        assert!(next.service_exited());
        assert_eq!(
            next.rejected_supervisor(),
            Some(Path::new("/state/supervisors/def/supervisor")),
            "the next boot sees the newer candidate, not the one already handled"
        );
    }

    #[test]
    fn an_interrupted_clear_gives_the_instance_it_took_back() {
        // Clearing takes the marker off its path with one rename so it can only ever destroy the
        // instance it took — which means a process death in that window parks an instance beside
        // the marker path. Reading is the only way to reach a marker, so reading restores it: an
        // exit whose rollback never committed must not be lost to a crash mid-clear.
        let state = dir("interrupted-clear");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let marker = state.join(control::SERVICE_EXITED_MARKER_FILE);
        let content = std::fs::read_to_string(&marker).unwrap();
        std::fs::rename(&marker, taken_path(&marker)).unwrap();

        let evidence = Evidence::read(Some(&state)).unwrap();

        assert!(evidence.service_exited(), "the taken instance is restored");
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), content);
        assert!(!taken_path(&marker).exists());
    }

    #[test]
    fn an_interrupted_clear_never_displaces_a_newer_marker() {
        // The parked instance is only ever evidence nobody has read, so a marker that has since
        // landed on the path is at least as new: it wins, and the stale copy is dropped rather
        // than renamed over it.
        let state = dir("interrupted-clear-superseded");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let marker = state.join(control::SERVICE_EXITED_MARKER_FILE);
        std::fs::rename(&marker, taken_path(&marker)).unwrap();
        write_markers(&state, "/state/supervisors/def/supervisor");
        let newest = std::fs::read_to_string(&marker).unwrap();

        assert!(Evidence::read(Some(&state)).unwrap().service_exited());

        assert_eq!(std::fs::read_to_string(&marker).unwrap(), newest);
        assert!(!taken_path(&marker).exists());
    }

    #[test]
    fn no_guardian_state_dir_means_no_evidence() {
        let mut evidence = Evidence::read(None).unwrap();
        assert!(!evidence.service_exited());
        assert!(evidence.rejected_supervisor().is_none());
        evidence.clear_service_exit().unwrap();
        evidence.clear_rejected_supervisor().unwrap();
    }

    #[test]
    fn a_corrupt_marker_is_discarded_rather_than_wedging_every_boot() {
        // A marker whose bytes are not evidence must never be able to fail a boot: reading it
        // would fail identically on every subsequent boot and the node could not start at all
        // without a human deleting the file. Unparseable evidence is no evidence — warn, drop it,
        // and boot.
        let state = dir("malformed");
        for garbage in [&b"one\ntwo\n"[..], b"", b"   \n", &[0xff, 0xfe][..]] {
            std::fs::write(state.join(control::REJECTED_SUPERVISOR_FILE), garbage).unwrap();
            let evidence = Evidence::read(Some(&state)).unwrap();
            assert!(evidence.rejected_supervisor().is_none());
            assert!(
                !exists(&state, control::REJECTED_SUPERVISOR_FILE),
                "the unusable marker is gone, so the next boot is not stuck on it"
            );
        }

        // Not even a regular file: same rule, and the boot still proceeds. A non-empty directory
        // is the hard case — unlinking one fails on every platform — and it must be REMOVED, not
        // merely tolerated, or every future boot repeats the same discard warning forever.
        let marker = state.join(control::SERVICE_EXITED_MARKER_FILE);
        std::fs::create_dir(&marker).unwrap();
        std::fs::write(marker.join("stray"), b"not evidence").unwrap();
        let evidence = Evidence::read(Some(&state)).unwrap();
        assert!(!evidence.service_exited());
        assert!(
            !marker.exists(),
            "a directory at the marker path must be discarded like any other garbage, so the \
             next boot is not stuck on it"
        );
    }

    #[test]
    fn a_corrupt_marker_rewritten_mid_boot_is_left_for_the_next_boot() {
        // Discarding garbage follows the same instance rule as clearing evidence: only the exact
        // bytes that were read are removed, so a real marker the guardian wrote in the meantime
        // survives to be acted on.
        let state = dir("malformed-rewritten");
        let path = state.join(control::REJECTED_SUPERVISOR_FILE);
        std::fs::write(&path, b"one\ntwo\n").unwrap();
        let claim = Marker::rejected_supervisor(&state)
            .claim()
            .unwrap()
            .unwrap();
        std::fs::write(&path, b"/state/supervisors/def/supervisor").unwrap();
        claim.discard_corrupt("is a test fixture");
        assert_eq!(
            Evidence::read(Some(&state)).unwrap().rejected_supervisor(),
            Some(Path::new("/state/supervisors/def/supervisor"))
        );
    }

    #[test]
    fn two_service_exits_with_the_same_shape_are_distinct_instances() {
        // The guardian stamps each exit uniquely, so the mid-boot rewrite check cannot be defeated
        // by two markers that happen to have the same length and land in the same clock tick —
        // which was every pair of them when the marker's content was empty.
        let state = dir("distinct-exits");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let first = Marker::service_exit(&state).claim().unwrap().unwrap();
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let second = Marker::service_exit(&state).claim().unwrap().unwrap();
        assert_ne!(first.content, second.content);
        first.clear().unwrap();
        assert!(
            exists(&state, control::SERVICE_EXITED_MARKER_FILE),
            "clearing the instance that was read must not erase the newer exit"
        );
        second.clear().unwrap();
        assert!(!exists(&state, control::SERVICE_EXITED_MARKER_FILE));
    }
}
