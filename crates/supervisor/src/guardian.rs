//! The agent's client for the launcher control channel.
//!
//! The launcher manages exactly one thing: which agent binary runs. It knows nothing about
//! workloads — those belong to the release's own reconciler — so this channel carries agent
//! readiness and agent-candidate handoff and nothing else. This module is the thin consumer side
//! of the frozen [`control`] protocol; the launcher is the server.
//!
//! Each operation is one synchronous request/response exchange. The launcher speaks
//! first with a [`Hello`], which [`Guardian::connect`] reads and negotiates before any
//! request; from then on every read is the response to the agent's last request.

use std::path::Path;

use control::{Hello, Nonce, Request, Response, CONTROL_ENV, READY_NONCE_ENV};

/// A connection to the launcher and this launch's readiness nonce.
pub(crate) struct Guardian {
    conn: Conn,
    ready_nonce: Nonce,
    /// Whether this launch has already sent `READY`. See [`Guardian::signal_ready`].
    ready_signalled: bool,
}

impl Guardian {
    /// Connect over the inherited channel and complete the handshake. Fails if the
    /// launcher did not launch this agent (no channel) or the protocols do not
    /// share a major.
    pub(crate) fn connect() -> Result<Guardian, String> {
        let ready_nonce = read_ready_nonce()?;
        let mut conn = Conn::inherit()?;
        let hello =
            Hello::read(conn.reader()).map_err(|e| format!("reading launcher hello: {e}"))?;
        if !hello.compatible() {
            return Err(format!(
                "control-protocol major mismatch (launcher speaks {}, agent speaks {})",
                hello.major,
                control::PROTOCOL_MAJOR
            ));
        }
        Ok(Guardian {
            conn,
            ready_nonce,
            ready_signalled: false,
        })
    }

    /// A connection in the shape [`Guardian::connect`] produces, over a socketpair whose other end
    /// the test drives.
    #[cfg(all(test, unix))]
    pub(crate) fn for_test(stream: std::os::unix::net::UnixStream) -> Guardian {
        Guardian {
            conn: Conn { stream },
            ready_nonce: [0u8; 16],
            ready_signalled: false,
        }
    }

    fn exchange(&mut self, req: &Request) -> Result<Response, GuardianError> {
        // A write/read failure on the channel is a transport failure, not a refusal: the
        // launcher died, the pipe broke, or a frame was truncated. Tag it `Channel` so the
        // update path recovers rather than blaming the candidate.
        req.write(self.conn.writer())
            .map_err(|e| GuardianError::Channel(format!("sending control request: {e}")))?;
        Response::read(self.conn.reader())
            .map_err(|e| GuardianError::Channel(format!("reading control response: {e}")))
    }

    /// Hand off to a staged replacement agent at `path`; the launcher relaunches
    /// from it under a readiness gate after this agent exits.
    pub(crate) fn replace_supervisor(&mut self, path: &Path) -> Result<(), GuardianError> {
        self.expect_ok(
            &Request::ReplaceSupervisor(path.as_os_str().to_os_string()),
            "REPLACE_SUPERVISOR",
        )
    }

    /// Prove this agent launch reached readiness (commits a candidate handoff), and hand back
    /// the proof that it was sent.
    ///
    /// A launcher that will not take the signal is warned about rather than fatal: this agent
    /// is already running and there is nothing better to do about it. The token is returned either
    /// way, because it records the *ordering* — that this call has happened — which is what the
    /// waits behind it depend on.
    ///
    /// At most one `READY` reaches the launcher per launch. Boot recovery signals readiness as
    /// soon as it starts waiting out a node-local transient (see `run`), and the boot path then
    /// signals again at its ordinary point; a second frame on the wire would be answered — the
    /// launcher's dispatch ignores it once the nonce is spent — but the agent would be
    /// blocked on that exchange for no reason, so the send is made once here instead.
    pub(crate) fn signal_ready(&mut self) -> ReadySignalled {
        if self.ready_signalled {
            return ReadySignalled(());
        }
        self.ready_signalled = true;
        if let Err(error) = self.expect_ok(&Request::Ready(self.ready_nonce), "READY") {
            crate::warn(&format!(
                "could not signal readiness to the launcher: {error}"
            ));
        }
        ReadySignalled(())
    }

    /// The `GuardianError` variant is preserved: a transport failure here is not the
    /// candidate's fault, and callers convert it into `io::ErrorKind::ConnectionReset` so boot
    /// recovery retries instead of rejecting the candidate's bytes.
    fn expect_ok(&mut self, req: &Request, what: &str) -> Result<(), GuardianError> {
        match self.exchange(req)? {
            Response::Ok => Ok(()),
            Response::Error(msg) => Err(GuardianError::Refused(format!(
                "launcher rejected {what}: {msg}"
            ))),
            other => Err(GuardianError::Refused(format!(
                "unexpected reply to {what}: {other:?}"
            ))),
        }
    }
}

/// Proof that this boot has already told the launcher the agent is ready. Only
/// [`Guardian::signal_ready`] can make one — the field is private to this module — so a wait that
/// demands one cannot be moved back in front of the readiness signal without failing to compile.
///
/// [`crate::secrets::SecretManager::acquire`] is that wait: in front of the signal, an unreachable
/// secrets endpoint is indistinguishable from an agent binary that cannot start, and the
/// candidate's bytes are then rejected by content hash, permanently.
pub(crate) struct ReadySignalled(());

#[cfg(test)]
impl ReadySignalled {
    /// Stand in for the launcher handshake, for tests of the waits that sit behind it.
    pub(crate) fn for_test() -> ReadySignalled {
        ReadySignalled(())
    }
}

/// Why a launcher request failed, distinguished by fault attribution. `Refused` is a real
/// operation failure the candidate owns (an operation this launcher build does not implement, an
/// unexpected reply). `Channel` is a control-channel transport failure — a SIGKILLed launcher, a
/// broken pipe, a closed or malformed frame — which is NEVER the candidate's fault. It maps to
/// `io::ErrorKind::ConnectionReset` so a caller can retry instead of permanently rejecting a
/// healthy release.
#[derive(Debug)]
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

/// The launcher's state directory, from the launch environment.
pub(crate) fn state_dir() -> Option<std::path::PathBuf> {
    std::env::var(control::STATE_DIR_ENV)
        .ok()
        .map(std::path::PathBuf::from)
}

/// One marker file the launcher writes for the agent: evidence about the agent launch that just
/// ended, which the agent turns into a durable rejection.
///
/// A marker is only ever obtained as a [`Claim`] — a specific *instance* of the file, pinned to
/// the bytes that were read — and a claim is the only thing that can erase one. Three hazards are
/// unrepresentable as a result:
///
/// * Consuming evidence by reading it. A crash or ENOSPC between the unlink and the durable write
///   the marker implies would erase the only record that a candidate agent failed its readiness
///   gate, and the next boot would re-stage the same bad bytes. Re-deriving evidence after a crash
///   is idempotent; re-creating deleted evidence is impossible.
/// * Erasing evidence nobody read. The launcher can write a *fresh* marker at any point during
///   boot reconciliation. Clearing "the marker file" would silently swallow that one; clearing a
///   claim touches only the instance whose contents drove this boot's decisions, and leaves a
///   newer instance for the next boot.
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
/// The *contents* are the instance identity, and nothing else: the launcher writes markers through
/// `foundation::durable::atomic_write_managed`, but filesystem metadata cannot tell two writes
/// apart portably (on Windows NTFS tunneling restores the creation time across the temp+rename,
/// modification time has ~15 ms granularity, and the length of a fixed-shape marker never varies).
/// So the marker's content is made self-identifying at the writer instead: the rejected-supervisor
/// marker carries the candidate's path — which is precisely the evidence, so two instances with
/// identical bytes say the same thing and have the same durable consequence.
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
            "could not restore the launcher marker {}: {error}",
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
        "launcher marker {} {why}; discarding it — it carries no evidence",
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
            "could not remove the unusable launcher marker {}: {error}",
            path.display()
        ));
    }
    None
}

impl Marker {
    /// A candidate agent failed its readiness gate; its staged path is the marker's content,
    /// and this agent records the rejection so the candidate is never staged again.
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
    /// If the bytes on disk are no longer the ones that were read, the launcher wrote a new marker
    /// while this boot was reconciling: that instance's evidence has been read by nobody, so it
    /// is left for the next boot.
    /// The instance is taken off the marker path in ONE atomic step (a rename) before its bytes are
    /// compared, so this call can only ever destroy the instance it took. Comparing in place and
    /// then unlinking the *path* leaves a window between the two calls in which a marker the
    /// launcher renamed into place is unlinked with its evidence read by nobody — which is
    /// precisely how a rejected candidate gets re-staged forever.
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
            "launcher marker {} was rewritten during boot reconciliation; leaving the new one \
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
                "could not remove the unusable launcher marker: {error}"
            ));
        }
    }
}

/// Everything the launcher left behind for this boot, read once, up front, and cleared once the
/// intent it implies becomes durable.
///
/// There is no way to reach a marker except through here, and no way to clear one except by
/// surrendering the claim that read it — so "cleared a marker whose consequence never committed"
/// and "cleared a marker nobody read" are both off the table by construction rather than by call
/// ordering.
pub(crate) struct Evidence {
    rejected_supervisor: Option<(Claim, std::path::PathBuf)>,
}

impl Evidence {
    /// Read the marker. `state_dir` is `None` when this agent was not launched by a launcher, in
    /// which case there is never any evidence.
    pub(crate) fn read(state_dir: Option<&Path>) -> std::io::Result<Evidence> {
        let Some(state_dir) = state_dir else {
            return Ok(Evidence {
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
                    // candidate the launcher will reject again (and record again, legibly);
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
            rejected_supervisor,
        })
    }

    /// The staged path of a candidate agent the launcher rejected at its readiness gate.
    pub(crate) fn rejected_supervisor(&self) -> Option<&Path> {
        self.rejected_supervisor
            .as_ref()
            .map(|(_, path)| path.as_path())
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
        format!("{READY_NONCE_ENV} not set; the agent must be launched by the launcher")
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
        // Safety: the launcher created this socketpair end and handed us its number
        // across exec; nothing else owns it.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        // The launcher cleared FD_CLOEXEC so this endpoint would survive *our* exec. Re-arm
        // it now that we own it, so it stops here: nothing we launch is a party to the
        // control protocol, and a descendant of the operator's lifecycle provider holding this
        // fd could drive the launcher directly — a handoff frame would swap the agent binary
        // out from under this node.
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
        // Safety: the launcher created these anonymous-pipe ends and handed us their
        // inheritable handle values across spawn; nothing else owns them.
        let conn = Conn {
            reader: unsafe { std::fs::File::from_raw_handle(r as RawHandle) },
            writer: unsafe { std::fs::File::from_raw_handle(w as RawHandle) },
        };
        // The launcher marked these ends inheritable so they would survive *our* spawn. Clear
        // it now that we own them, so the channel stops here: nothing we launch is a party to
        // the control protocol, and a descendant of the operator's lifecycle provider holding
        // these handles could drive the launcher directly — a handoff frame would swap the agent
        // binary out from under this node. This is the exact counterpart of the unix arm's
        // FD_CLOEXEC re-arm; the launcher cannot do it for us, because the flag travels with the
        // handle into this process.
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

/// Answer one request the way the launcher would, and hand it back, so the exchange under test
/// completes and the frame it put on the wire can be asserted on.
#[cfg(all(test, unix))]
fn answering(
    mut peer: std::os::unix::net::UnixStream,
    response: Response,
) -> std::thread::JoinHandle<Request> {
    std::thread::spawn(move || {
        let request = Request::read(&mut peer).expect("one request");
        response.write(&mut peer).expect("one response");
        request
    })
}

/// The connection's own bookkeeping, driven over a real socketpair with a stand-in launcher
/// answering one request. Unix-only because the channel endpoint is: on Windows it is a pair of
/// anonymous pipe handles, and the state under test lives above that split.
#[cfg(all(test, unix))]
mod channel_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_handoff_puts_the_candidate_path_on_the_wire() {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let peer = answering(theirs, Response::Ok);
        let mut guardian = Guardian::for_test(ours);

        guardian
            .replace_supervisor(Path::new("/state/supervisors/abc/updated-agent"))
            .expect("the launcher accepts the handoff");

        assert_eq!(
            peer.join().expect("the stand-in launcher"),
            Request::ReplaceSupervisor("/state/supervisors/abc/updated-agent".into())
        );
    }

    #[test]
    fn readiness_is_signalled_at_most_once_per_launch() {
        // Boot recovery signals as soon as it starts waiting out a node-local transient, and the
        // boot path signals again at its ordinary point. A second frame would be answered — the
        // launcher ignores a spent nonce — but this agent would block on an exchange for nothing.
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        let peer = answering(theirs, Response::Ok);
        let mut guardian = Guardian::for_test(ours);

        guardian.signal_ready();
        guardian.signal_ready();

        assert_eq!(
            peer.join().expect("the stand-in launcher"),
            Request::Ready([0u8; 16]),
            "exactly one READY reached the launcher"
        );
    }

    #[test]
    fn a_dead_channel_is_a_transport_failure_not_a_refusal() {
        // The distinction the whole error type exists for: a candidate agent must never be
        // rejected by content hash because the launcher's socket died.
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        drop(theirs);
        let mut guardian = Guardian::for_test(ours);

        let error = guardian
            .replace_supervisor(Path::new("/state/supervisors/abc/updated-agent"))
            .expect_err("the channel is gone");

        assert!(matches!(error, GuardianError::Channel(_)));
        assert_eq!(
            std::io::Error::from(error).kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    fn dir(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let path = guard.path().join(name);
        std::fs::create_dir_all(&path).unwrap();
        (guard, path)
    }

    /// Stand in for the launcher's write (`launcher::record`): the rejected candidate's path.
    fn write_markers(state: &Path, candidate: &str) {
        foundation::durable::atomic_write_managed(
            &state.join(control::REJECTED_SUPERVISOR_FILE),
            ".launcher-",
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
        // crash between them re-derives the same rejection rather than losing it.
        let (_guard, state) = dir("rejected-supervisor");
        write_markers(&state, "/state/supervisors/abc/supervisor");

        let mut evidence = Evidence::read(Some(&state)).unwrap();
        assert_eq!(
            evidence.rejected_supervisor(),
            Some(Path::new("/state/supervisors/abc/supervisor"))
        );
        assert!(
            Evidence::read(Some(&state))
                .unwrap()
                .rejected_supervisor()
                .is_some(),
            "a re-read still sees the marker"
        );

        evidence.clear_rejected_supervisor().unwrap();
        assert!(!exists(&state, control::REJECTED_SUPERVISOR_FILE));
        // Consumed: a second clear is a no-op, not a second unlink of whatever is there now.
        evidence.clear_rejected_supervisor().unwrap();
    }

    #[test]
    fn a_marker_written_during_reconciliation_is_never_cleared_unread() {
        // The launcher can reject a fresh candidate at any point while this boot reconciles.
        // Clearing must erase only the instance this boot actually read; the new one is the next
        // boot's evidence, and losing it would let the same bad bytes be staged again.
        let (_guard, state) = dir("rewritten");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let mut evidence = Evidence::read(Some(&state)).unwrap();

        // The launcher writes a new marker mid-boot (a fresh file renamed into place).
        write_markers(&state, "/state/supervisors/def/supervisor");

        evidence.clear_rejected_supervisor().unwrap();
        assert!(
            exists(&state, control::REJECTED_SUPERVISOR_FILE),
            "the marker written during reconciliation must survive"
        );
        assert_eq!(
            Evidence::read(Some(&state)).unwrap().rejected_supervisor(),
            Some(Path::new("/state/supervisors/def/supervisor")),
            "the next boot sees the newer candidate, not the one already handled"
        );
    }

    #[test]
    fn an_interrupted_clear_gives_the_instance_it_took_back() {
        // Clearing takes the marker off its path with one rename so it can only ever destroy the
        // instance it took — which means a process death in that window parks an instance beside
        // the marker path. Reading is the only way to reach a marker, so reading restores it: a
        // rejection that never committed must not be lost to a crash mid-clear.
        let (_guard, state) = dir("interrupted-clear");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let marker = state.join(control::REJECTED_SUPERVISOR_FILE);
        let content = std::fs::read_to_string(&marker).unwrap();
        std::fs::rename(&marker, taken_path(&marker)).unwrap();

        let evidence = Evidence::read(Some(&state)).unwrap();

        assert!(
            evidence.rejected_supervisor().is_some(),
            "the taken instance is restored"
        );
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), content);
        assert!(!taken_path(&marker).exists());
    }

    #[test]
    fn an_interrupted_clear_never_displaces_a_newer_marker() {
        // The parked instance is only ever evidence nobody has read, so a marker that has since
        // landed on the path is at least as new: it wins, and the stale copy is dropped rather
        // than renamed over it.
        let (_guard, state) = dir("interrupted-clear-superseded");
        write_markers(&state, "/state/supervisors/abc/supervisor");
        let marker = state.join(control::REJECTED_SUPERVISOR_FILE);
        std::fs::rename(&marker, taken_path(&marker)).unwrap();
        write_markers(&state, "/state/supervisors/def/supervisor");
        let newest = std::fs::read_to_string(&marker).unwrap();

        assert!(Evidence::read(Some(&state))
            .unwrap()
            .rejected_supervisor()
            .is_some());

        assert_eq!(std::fs::read_to_string(&marker).unwrap(), newest);
        assert!(!taken_path(&marker).exists());
    }

    #[test]
    fn no_launcher_state_dir_means_no_evidence() {
        let mut evidence = Evidence::read(None).unwrap();
        assert!(evidence.rejected_supervisor().is_none());
        evidence.clear_rejected_supervisor().unwrap();
    }

    #[test]
    fn a_corrupt_marker_is_discarded_rather_than_wedging_every_boot() {
        // A marker whose bytes are not evidence must never be able to fail a boot: reading it
        // would fail identically on every subsequent boot and the node could not start at all
        // without a human deleting the file. Unparseable evidence is no evidence — warn, drop it,
        // and boot.
        let (_guard, state) = dir("malformed");
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
        let marker = state.join(control::REJECTED_SUPERVISOR_FILE);
        std::fs::create_dir(&marker).unwrap();
        std::fs::write(marker.join("stray"), b"not evidence").unwrap();
        let evidence = Evidence::read(Some(&state)).unwrap();
        assert!(evidence.rejected_supervisor().is_none());
        assert!(
            !marker.exists(),
            "a directory at the marker path must be discarded like any other garbage, so the \
             next boot is not stuck on it"
        );
    }

    #[test]
    fn a_corrupt_marker_rewritten_mid_boot_is_left_for_the_next_boot() {
        // Discarding garbage follows the same instance rule as clearing evidence: only the exact
        // bytes that were read are removed, so a real marker the launcher wrote in the meantime
        // survives to be acted on.
        let (_guard, state) = dir("malformed-rewritten");
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
}
