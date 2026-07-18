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
        })
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

    fn exchange(&mut self, req: &Request) -> Result<Response, String> {
        req.write(self.conn.writer())
            .map_err(|e| format!("sending control request: {e}"))?;
        Response::read(self.conn.reader()).map_err(|e| format!("reading control response: {e}"))
    }

    /// Ask the guardian to launch the application from `spec`. Returns the application's
    /// PID.
    pub(crate) fn launch(&mut self, spec: &CommandSpec) -> Result<u32, String> {
        self.require(control::CAP_LAUNCH_APP_V1, "LAUNCH")?;
        match self.exchange(&Request::Launch(spec.clone()))? {
            Response::Launched { pid } => Ok(pid),
            Response::Error(msg) => {
                Err(format!("guardian could not launch the application: {msg}"))
            }
            other => Err(format!("unexpected reply to LAUNCH: {other:?}")),
        }
    }

    /// Stop the application (the guardian escalates to a hard kill). Used to quiesce it
    /// before activating a release during an update.
    pub(crate) fn stop(&mut self) -> Result<(), String> {
        self.require(control::CAP_STOP_APP, "STOP")?;
        self.expect_ok(&Request::Stop, "STOP")
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

    /// Prove this supervisor launch reached readiness (commits a candidate handoff).
    pub(crate) fn signal_ready(&mut self) -> Result<(), String> {
        self.require(control::CAP_READY, "READY")?;
        self.expect_ok(&Request::Ready(self.ready_nonce), "READY")
    }

    fn expect_ok(&mut self, req: &Request, what: &str) -> Result<(), String> {
        match self.exchange(req)? {
            Response::Ok => Ok(()),
            Response::Error(msg) => Err(format!("guardian rejected {what}: {msg}")),
            other => Err(format!("unexpected reply to {what}: {other:?}")),
        }
    }
}

/// The application PID the guardian is already running, if any (a supervisor
/// crash-relaunch or candidate activation), so the supervisor adopts rather than
/// launching a duplicate.
pub(crate) fn adopted_app_pid() -> Option<u32> {
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

/// Read and clear the guardian's crash marker: `true` if the last application exit was a
/// crash (so an unconfirmed update should revert to its predecessor).
pub(crate) fn take_crash_marker(state_dir: &Path) -> std::io::Result<bool> {
    let path = state_dir.join(control::CRASH_MARKER_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            foundation::durable::remove_file(&path)?;
            Ok(true)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("crash marker {} is not a regular file", path.display()),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Read and clear the guardian's rejected-supervisor marker: the path of a candidate
/// supervisor that failed its readiness gate, so this supervisor records the rejection.
pub(crate) fn take_rejected_supervisor(
    state_dir: &Path,
) -> std::io::Result<Option<std::path::PathBuf>> {
    let path = state_dir.join(control::REJECTED_SUPERVISOR_FILE);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    foundation::durable::remove_file(&path)?;
    let trimmed = content.trim();
    if trimmed.is_empty() || content.lines().count() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rejected-supervisor marker is malformed",
        ));
    }
    Ok(Some(std::path::PathBuf::from(trimmed)))
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
        Ok(Conn {
            reader: unsafe { std::fs::File::from_raw_handle(r as RawHandle) },
            writer: unsafe { std::fs::File::from_raw_handle(w as RawHandle) },
        })
    }

    fn reader(&mut self) -> &mut std::fs::File {
        &mut self.reader
    }

    fn writer(&mut self) -> &mut std::fs::File {
        &mut self.writer
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

    #[test]
    fn crash_marker_is_consumed_once() {
        let state = dir("crash");
        std::fs::write(state.join(control::CRASH_MARKER_FILE), b"crashed\n").unwrap();
        assert!(take_crash_marker(&state).unwrap());
        assert!(!take_crash_marker(&state).unwrap());
    }

    #[test]
    fn malformed_markers_fail_closed() {
        let state = dir("malformed");
        std::fs::create_dir(state.join(control::CRASH_MARKER_FILE)).unwrap();
        assert!(take_crash_marker(&state).is_err());
        std::fs::write(state.join(control::REJECTED_SUPERVISOR_FILE), b"one\ntwo\n").unwrap();
        assert!(take_rejected_supervisor(&state).is_err());
    }
}
