//! Versioned guardian⇄supervisor control protocol. The std-only crate is shared by
//! both processes so framing and compatibility rules cannot drift.
//!
//! ## Framing (the hard-to-change layer)
//!
//! Every channel opens with [`MAGIC`] and [`FRAMING_VERSION`]. Each message is
//! `[u32 length BE][u8 tag][body]`, with `length` capped at [`MAX_FRAME`] and every
//! string/list length-prefixed and bounded.
//!
//! ## Negotiation (the extensible layer)
//!
//! The guardian sends [`Hello`]; the supervisor chooses the highest shared major and
//! uses only advertised capabilities. Unknown requests receive
//! [`Response::Unsupported`].
//!
//! ## Platform-native strings
//!
//! [`CommandSpec`] preserves raw Unix bytes and Windows UTF-16/WTF-16 code units.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};

/// Identifies an `updated` guardian control channel. Fixed forever.
pub const MAGIC: [u8; 4] = *b"UGRD";
/// Version of the framing layer itself (length-prefix + preamble rules).
pub const FRAMING_VERSION: u8 = 1;

/// The inherited control-channel endpoint: a file-descriptor number on Unix, a handle
/// value on Windows.
pub const CONTROL_ENV: &str = "UPDATED_CONTROL";
/// Hex of the nonce the supervisor must echo in [`Request::Ready`] to prove *this*
/// launch reached readiness.
pub const READY_NONCE_ENV: &str = "UPDATED_READY_NONCE";
/// Set to the running application's PID when the guardian launches a supervisor while
/// it already owns a running app (a supervisor crash-relaunch, or a candidate activation).
/// The new supervisor adopts that app instead of launching a duplicate; absent means no
/// app is running yet, so the supervisor launches one. The guardian owns the process, so
/// the PID is authoritative — no identity handshake is needed.
pub const APP_PID_ENV: &str = "UPDATED_APP_PID";
/// The guardian's state directory, so the supervisor knows where to stage a
/// replacement supervisor binary (`<state>/supervisors/<id>/`).
pub const STATE_DIR_ENV: &str = "UPDATED_STATE_DIR";

/// Filename, under the state directory, the guardian touches when it rolls up a crashed
/// application; the supervisor reads and clears it on recovery to revert an unconfirmed update. A
/// shared filename (not a wire message) since both sides agree on the layout.
pub const CRASH_MARKER_FILE: &str = "app-crashed";
/// Filename, under the state directory, into which the guardian writes the path of a
/// replacement supervisor that failed its readiness gate (so the guardian rolled the
/// `desired-supervisor` pointer back). The supervisor reads it on recovery and records
/// the *rejection* — the guardian keeps no rejection set of its own, only this one dumb
/// marker; deciding what it means is the supervisor's job.
pub const REJECTED_SUPERVISOR_FILE: &str = "rejected-supervisor";

/// The protocol major this build implements.
pub const PROTOCOL_MAJOR: u16 = 1;
/// The protocol minor this build implements.
pub const PROTOCOL_MINOR: u16 = 0;

/// Maximum framed message size. A command spec (argv + full environment) is the
/// largest message and is comfortably under this; the cap only bounds a malformed peer.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_ITEMS: u32 = 65_536;
const MAX_STR_UNITS: u32 = 1 << 20;

pub const CAP_LAUNCH_APP_V1: u16 = 1;
pub const CAP_STOP_APP: u16 = 2;
pub const CAP_REPLACE_SUPERVISOR_V1: u16 = 3;
pub const CAP_READY: u16 = 4;

/// Everything the current guardian build advertises.
const CURRENT_CAPS: &[u16] = &[
    CAP_LAUNCH_APP_V1,
    CAP_STOP_APP,
    CAP_REPLACE_SUPERVISOR_V1,
    CAP_READY,
];

/// A supervisor readiness nonce: 16 random bytes minted per supervisor launch and
/// echoed in [`Request::Ready`], correlating readiness with the exact candidate.
pub type Nonce = [u8; 16];

const TAG_LAUNCH: u8 = 0x01;
const TAG_STOP: u8 = 0x02;
const TAG_REPLACE: u8 = 0x03;
const TAG_READY: u8 = 0x04;

const TAG_OK: u8 = 0x81;
const TAG_ERROR: u8 = 0x82;
const TAG_LAUNCHED: u8 = 0x83;
const TAG_UNSUPPORTED: u8 = 0x84;

/// The guardian's opening message: what protocol majors and capabilities it offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub majors: Vec<u16>,
    pub minor: u16,
    pub capabilities: Vec<u16>,
}

/// The negotiated result on the supervisor side: the shared major plus the set of
/// capabilities the peer guardian advertised. All feature decisions go through
/// [`Capabilities::supports`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub major: u16,
    pub guardian_minor: u16,
    caps: Vec<u16>,
}

impl Hello {
    /// The current build's advertisement (guardian side).
    pub fn current() -> Hello {
        Hello {
            majors: vec![PROTOCOL_MAJOR],
            minor: PROTOCOL_MINOR,
            capabilities: CURRENT_CAPS.to_vec(),
        }
    }

    /// Write the fixed preamble followed by this hello (guardian side).
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&[FRAMING_VERSION])?;
        let mut body = Vec::new();
        put_u16_list(&mut body, &self.majors);
        put_u16(&mut body, self.minor);
        put_u16_list(&mut body, &self.capabilities);
        write_frame(w, &body)?;
        Ok(())
    }

    /// Read and validate the preamble, then the hello (supervisor side).
    pub fn read(r: &mut impl Read) -> Result<Hello> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(Error::Incompatible("not an updated control channel"));
        }
        let mut fv = [0u8; 1];
        r.read_exact(&mut fv)?;
        if fv[0] != FRAMING_VERSION {
            return Err(Error::Incompatible("unknown framing version"));
        }
        let body = read_frame(r)?;
        let mut at = 0usize;
        let majors = get_u16_list(&body, &mut at)?;
        let minor = get_u16(&body, &mut at)?;
        let capabilities = get_u16_list(&body, &mut at)?;
        Ok(Hello {
            majors,
            minor,
            capabilities,
        })
    }

    /// Negotiate from the supervisor's supported majors, choosing the highest shared
    /// one. `None` means no common major — an upgrade needs a bridge supervisor.
    pub fn negotiate(&self, supported_majors: &[u16]) -> Option<Capabilities> {
        let major = self
            .majors
            .iter()
            .copied()
            .filter(|m| supported_majors.contains(m))
            .max()?;
        Some(Capabilities {
            major,
            guardian_minor: self.minor,
            caps: self.capabilities.clone(),
        })
    }
}

impl Capabilities {
    /// Whether the guardian advertised `cap` (e.g. [`CAP_LAUNCH_APP_V1`]).
    pub fn supports(&self, cap: u16) -> bool {
        self.caps.contains(&cap)
    }
}

/// What the supervisor can ask the guardian to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Launch the application from this exact spec.
    Launch(CommandSpec),
    /// Stop the application (SIGTERM to its group on Unix; terminate on Windows). Used
    /// to quiesce it before swapping its binary during an update — an *intentional*
    /// exit, which the guardian does not treat as a crash.
    Stop,
    /// Hand off to the staged replacement supervisor at this opaque path.
    ReplaceSupervisor(OsString),
    /// This supervisor has initialized; the nonce proves it is *this* launch.
    Ready(Nonce),
}

/// The guardian's reply to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// A non-launch request succeeded.
    Ok,
    /// The request failed; the string is a human-readable reason (diagnostics only).
    Error(String),
    /// Answer to [`Request::Launch`]: the application is running, with this PID.
    Launched { pid: u32 },
    /// The guardian does not implement the requested operation.
    Unsupported,
}

/// A fully-specified process launch, in platform-native strings. The guardian applies
/// it verbatim — `program` as the image, `args` as `argv[1..]`, `env` as the complete
/// environment (nothing inherited but standard I/O), `cwd` if present — and interprets
/// none of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<OsString>,
}

/// A framing/format fault. Never a reason to change the protocol.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The peer closed the channel cleanly at a frame boundary.
    Closed,
    /// The frame violated the format (oversized length, truncated body, bad discriminant).
    Malformed(&'static str),
    /// A message tag this build does not know. Surfaced (not fatal) so a request
    /// reader can answer [`Response::Unsupported`].
    UnknownTag(u8),
    /// The channel's framing or protocol major is not one this build can speak.
    Incompatible(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "control i/o: {e}"),
            Error::Closed => write!(f, "control channel closed"),
            Error::Malformed(what) => write!(f, "malformed control frame: {what}"),
            Error::UnknownTag(t) => write!(f, "unknown message tag {t:#04x}"),
            Error::Incompatible(what) => write!(f, "incompatible control channel: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ── framing ──────────────────────────────────────────────────────────────────────

fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(Error::Malformed("frame exceeds MAX_FRAME"));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    match r.read(&mut len[..1]) {
        Ok(0) => return Err(Error::Closed),
        Ok(_) => {}
        // Nothing arrived within the transport's read timeout. The channel is merely idle
        // and still frame-aligned, so this is an ordinary i/o condition the reader retries.
        Err(e) => return Err(Error::Io(e)),
    }
    // Past that first byte the peer has committed to a frame. A stall from here is a
    // *truncated* frame, not an idle channel: the stream is desynced and no later read can
    // resume it, so report it as malformed. Without this a peer that sends one byte and
    // stops would block a single-threaded reader inside `read_exact` forever — the guardian
    // would stop servicing its shutdown signal, its application-crash check, and its
    // readiness deadline, all while holding the application.
    read_framed(r, &mut len[1..])?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(Error::Malformed("frame exceeds MAX_FRAME"));
    }
    let mut buf = vec![0u8; len];
    read_framed(r, &mut buf)?;
    Ok(buf)
}

/// Read the remainder of a frame the peer has already begun. A timeout here means the peer
/// stalled mid-frame, which is unrecoverable for a stream protocol — the reader cannot know
/// where the next frame starts — so it is malformed rather than a retryable i/o error.
fn read_framed(r: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            Error::Malformed("peer stalled mid-frame")
        }
        _ => Error::Io(e),
    })
}

// ── primitive codecs ───────────────────────────────────────────────────────────

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u16(buf: &[u8], at: &mut usize) -> Result<u16> {
    let end = at
        .checked_add(2)
        .ok_or(Error::Malformed("length overflow"))?;
    let slice = buf.get(*at..end).ok_or(Error::Malformed("truncated u16"))?;
    *at = end;
    Ok(u16::from_be_bytes(slice.try_into().unwrap()))
}

fn put_u16_list(out: &mut Vec<u8>, items: &[u16]) {
    put_u32(out, items.len() as u32);
    for &v in items {
        put_u16(out, v);
    }
}

fn get_u16_list(buf: &[u8], at: &mut usize) -> Result<Vec<u16>> {
    let n = get_u32(buf, at)?;
    if n > MAX_ITEMS {
        return Err(Error::Malformed("list exceeds MAX_ITEMS"));
    }
    (0..n).map(|_| get_u16(buf, at)).collect()
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn get_u32(buf: &[u8], at: &mut usize) -> Result<u32> {
    let end = at
        .checked_add(4)
        .ok_or(Error::Malformed("length overflow"))?;
    let slice = buf.get(*at..end).ok_or(Error::Malformed("truncated u32"))?;
    *at = end;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}

fn put_os(out: &mut Vec<u8>, s: &OsStr) {
    let (unit_count, bytes) = os_units(s);
    put_u32(out, unit_count);
    out.extend_from_slice(&bytes);
}

fn get_os(buf: &[u8], at: &mut usize) -> Result<OsString> {
    let units = get_u32(buf, at)?;
    if units > MAX_STR_UNITS {
        return Err(Error::Malformed("string exceeds MAX_STR_UNITS"));
    }
    let byte_len = os_byte_len(units)?;
    let end = at
        .checked_add(byte_len)
        .ok_or(Error::Malformed("string length overflow"))?;
    let slice = buf
        .get(*at..end)
        .ok_or(Error::Malformed("truncated string"))?;
    let s = os_from_units(slice)?;
    *at = end;
    Ok(s)
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn get_str(buf: &[u8], at: &mut usize) -> Result<String> {
    let len = get_u32(buf, at)? as usize;
    if len as u32 > MAX_STR_UNITS {
        return Err(Error::Malformed("string exceeds MAX_STR_UNITS"));
    }
    let end = at
        .checked_add(len)
        .ok_or(Error::Malformed("length overflow"))?;
    let slice = buf
        .get(*at..end)
        .ok_or(Error::Malformed("truncated string"))?;
    let s = std::str::from_utf8(slice)
        .map_err(|_| Error::Malformed("invalid utf-8"))?
        .to_string();
    *at = end;
    Ok(s)
}

fn put_list(out: &mut Vec<u8>, items: &[OsString]) {
    put_u32(out, items.len() as u32);
    for item in items {
        put_os(out, item);
    }
}

fn get_list(buf: &[u8], at: &mut usize) -> Result<Vec<OsString>> {
    let n = get_u32(buf, at)?;
    if n > MAX_ITEMS {
        return Err(Error::Malformed("list exceeds MAX_ITEMS"));
    }
    (0..n).map(|_| get_os(buf, at)).collect()
}

fn get_nonce(buf: &[u8], at: &mut usize) -> Result<Nonce> {
    let end = at
        .checked_add(16)
        .ok_or(Error::Malformed("nonce overflow"))?;
    let slice = buf
        .get(*at..end)
        .ok_or(Error::Malformed("truncated nonce"))?;
    *at = end;
    Ok(slice.try_into().unwrap())
}

fn put_spec(out: &mut Vec<u8>, spec: &CommandSpec) {
    put_os(out, &spec.program);
    put_list(out, &spec.args);
    put_u32(out, spec.env.len() as u32);
    for (k, v) in &spec.env {
        put_os(out, k);
        put_os(out, v);
    }
    match &spec.cwd {
        Some(cwd) => {
            out.push(1);
            put_os(out, cwd);
        }
        None => out.push(0),
    }
}

fn get_spec(buf: &[u8], at: &mut usize) -> Result<CommandSpec> {
    let program = get_os(buf, at)?;
    let args = get_list(buf, at)?;
    let env_n = get_u32(buf, at)?;
    if env_n > MAX_ITEMS {
        return Err(Error::Malformed("env exceeds MAX_ITEMS"));
    }
    let mut env = Vec::with_capacity(env_n as usize);
    for _ in 0..env_n {
        let k = get_os(buf, at)?;
        let v = get_os(buf, at)?;
        env.push((k, v));
    }
    let cwd = match buf.get(*at) {
        Some(0) => {
            *at += 1;
            None
        }
        Some(1) => {
            *at += 1;
            Some(get_os(buf, at)?)
        }
        _ => return Err(Error::Malformed("bad cwd discriminant")),
    };
    Ok(CommandSpec {
        program,
        args,
        env,
        cwd,
    })
}

// ── message encode/decode ────────────────────────────────────────────────────────
// Decoders read the fields they know and ignore any trailing bytes, so a future minor
// can append optional fields without breaking an older reader (forward-compat).

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Request::Launch(spec) => {
                out.push(TAG_LAUNCH);
                put_spec(&mut out, spec);
            }
            Request::Stop => out.push(TAG_STOP),
            Request::ReplaceSupervisor(path) => {
                out.push(TAG_REPLACE);
                put_os(&mut out, path);
            }
            Request::Ready(nonce) => {
                out.push(TAG_READY);
                out.extend_from_slice(nonce);
            }
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Request> {
        let (&tag, body) = buf.split_first().ok_or(Error::Malformed("empty frame"))?;
        let mut at = 0usize;
        let req = match tag {
            TAG_LAUNCH => Request::Launch(get_spec(body, &mut at)?),
            TAG_STOP => Request::Stop,
            TAG_REPLACE => Request::ReplaceSupervisor(get_os(body, &mut at)?),
            TAG_READY => Request::Ready(get_nonce(body, &mut at)?),
            other => return Err(Error::UnknownTag(other)),
        };
        Ok(req)
    }

    /// Write this request as one frame (supervisor side).
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        write_frame(w, &self.encode())
    }

    /// Read one request frame (guardian side). `Err(UnknownTag)` on an operation this
    /// build does not know — the guardian answers [`Response::Unsupported`].
    pub fn read(r: &mut impl Read) -> Result<Request> {
        Request::decode(&read_frame(r)?)
    }
}

impl Response {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Response::Ok => out.push(TAG_OK),
            Response::Error(msg) => {
                out.push(TAG_ERROR);
                put_str(&mut out, msg);
            }
            Response::Launched { pid } => {
                out.push(TAG_LAUNCHED);
                put_u32(&mut out, *pid);
            }
            Response::Unsupported => out.push(TAG_UNSUPPORTED),
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Response> {
        let (&tag, body) = buf.split_first().ok_or(Error::Malformed("empty frame"))?;
        let mut at = 0usize;
        let resp = match tag {
            TAG_OK => Response::Ok,
            TAG_ERROR => Response::Error(get_str(body, &mut at)?),
            TAG_LAUNCHED => Response::Launched {
                pid: get_u32(body, &mut at)?,
            },
            TAG_UNSUPPORTED => Response::Unsupported,
            other => return Err(Error::UnknownTag(other)),
        };
        Ok(resp)
    }

    /// Write this response as one frame (guardian side).
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        write_frame(w, &self.encode())
    }

    /// Read one response frame (supervisor side).
    pub fn read(r: &mut impl Read) -> Result<Response> {
        Response::decode(&read_frame(r)?)
    }
}

// ── platform-native string units ─────────────────────────────────────────────────

#[cfg(unix)]
fn os_units(s: &OsStr) -> (u32, Vec<u8>) {
    use std::os::unix::ffi::OsStrExt;
    let bytes = s.as_bytes().to_vec();
    (bytes.len() as u32, bytes)
}

#[cfg(unix)]
fn os_byte_len(units: u32) -> Result<usize> {
    Ok(units as usize)
}

#[cfg(unix)]
fn os_from_units(bytes: &[u8]) -> Result<OsString> {
    use std::os::unix::ffi::OsStrExt;
    Ok(OsStr::from_bytes(bytes).to_os_string())
}

#[cfg(windows)]
fn os_units(s: &OsStr) -> (u32, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = s.encode_wide().collect();
    let unit_count = wide.len() as u32;
    let bytes = wide.into_iter().flat_map(u16::to_le_bytes).collect();
    (unit_count, bytes)
}

#[cfg(windows)]
fn os_byte_len(units: u32) -> Result<usize> {
    (units as usize)
        .checked_mul(2)
        .ok_or(Error::Malformed("utf-16 length overflow"))
}

#[cfg(windows)]
fn os_from_units(bytes: &[u8]) -> Result<OsString> {
    use std::os::windows::ffi::OsStringExt;
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Malformed("odd utf-16 byte length"));
    }
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(OsString::from_wide(&wide))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> CommandSpec {
        CommandSpec {
            program: OsString::from("/opt/app/bin/server"),
            args: vec![OsString::from("--addr"), OsString::from("127.0.0.1:8080")],
            env: vec![
                (OsString::from("PATH"), OsString::from("/usr/bin")),
                (
                    OsString::from("UPDATED_HEALTH_TOKEN"),
                    OsString::from("abc"),
                ),
            ],
            cwd: Some(OsString::from("/opt/app")),
        }
    }

    #[test]
    fn os_string_length_prefix_counts_native_units() {
        // In particular, Windows serializes UTF-16 units as two bytes each. The wire
        // prefix counts units, not bytes; otherwise the decoder consumes the following
        // field as part of the string.
        let (units, bytes) = os_units(OsStr::new("A😀"));
        assert_eq!(bytes.len(), os_byte_len(units).unwrap());
    }

    fn round_trip_request(req: Request) {
        let mut buf = Vec::new();
        req.write(&mut buf).unwrap();
        assert_eq!(Request::read(&mut &buf[..]).unwrap(), req);
    }

    fn round_trip_response(resp: Response) {
        let mut buf = Vec::new();
        resp.write(&mut buf).unwrap();
        assert_eq!(Response::read(&mut &buf[..]).unwrap(), resp);
    }

    #[test]
    fn requests_round_trip() {
        round_trip_request(Request::Launch(spec()));
        round_trip_request(Request::Stop);
        round_trip_request(Request::ReplaceSupervisor(OsString::from(
            "/var/lib/app/supervisors/deadbeef/supervisor",
        )));
        round_trip_request(Request::Ready([0xABu8; 16]));
    }

    #[test]
    fn responses_round_trip() {
        round_trip_response(Response::Ok);
        round_trip_response(Response::Error("could not launch: ENOENT".into()));
        round_trip_response(Response::Launched { pid: 4321 });
        round_trip_response(Response::Unsupported);
    }

    #[test]
    fn handshake_negotiates_the_shared_major_and_capabilities() {
        let mut wire = Vec::new();
        Hello::current().write(&mut wire).unwrap();
        let hello = Hello::read(&mut &wire[..]).unwrap();
        assert_eq!(hello, Hello::current());
        let caps = hello.negotiate(&[1]).expect("shared major 1");
        assert_eq!(caps.major, 1);
        assert!(caps.supports(CAP_LAUNCH_APP_V1));
        assert!(caps.supports(CAP_REPLACE_SUPERVISOR_V1));
        assert!(!caps.supports(0xFFFF));
    }

    #[test]
    fn negotiation_without_a_shared_major_fails_closed() {
        let hello = Hello {
            majors: vec![2, 3],
            minor: 0,
            capabilities: vec![CAP_LAUNCH_APP_V1],
        };
        assert!(hello.negotiate(&[1]).is_none());
        assert_eq!(
            hello.negotiate(&[1, 2, 3]).unwrap().major,
            3,
            "picks highest"
        );
    }

    #[test]
    fn wrong_magic_or_framing_is_incompatible() {
        let mut bad = b"XXXX".to_vec();
        bad.push(FRAMING_VERSION);
        assert!(matches!(
            Hello::read(&mut &bad[..]),
            Err(Error::Incompatible(_))
        ));
        let mut bad = MAGIC.to_vec();
        bad.push(99);
        assert!(matches!(
            Hello::read(&mut &bad[..]),
            Err(Error::Incompatible(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_tolerated_as_future_optional_fields() {
        let launch = Request::Launch(spec());
        let mut payload = launch.encode();
        payload.extend_from_slice(b"a future optional field");
        let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&payload);
        assert_eq!(Request::read(&mut &framed[..]).unwrap(), launch);
    }

    #[test]
    fn unknown_tag_surfaces_so_the_guardian_can_answer_unsupported() {
        let mut framed = 1u32.to_be_bytes().to_vec();
        framed.push(0x77);
        assert!(matches!(
            Request::read(&mut &framed[..]),
            Err(Error::UnknownTag(0x77))
        ));
    }

    #[test]
    fn oversized_length_prefix_is_rejected_without_allocating() {
        let mut framed = (u32::MAX).to_be_bytes().to_vec();
        framed.push(TAG_STOP);
        assert!(matches!(
            Request::read(&mut &framed[..]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn empty_and_absent_cwd_are_distinct() {
        let mut a = spec();
        a.cwd = None;
        let mut b = spec();
        b.cwd = Some(OsString::new());
        round_trip_request(Request::Launch(a.clone()));
        round_trip_request(Request::Launch(b.clone()));
        assert_ne!(a, b);
    }

    #[test]
    fn clean_eof_at_a_boundary_is_closed_not_error() {
        let empty: &[u8] = &[];
        assert!(matches!(Request::read(&mut &empty[..]), Err(Error::Closed)));
    }

    #[test]
    fn max_frame_is_exactly_four_mib() {
        // The cap is part of the wire contract; a drifted arithmetic constant would let
        // a peer negotiate a different ceiling than the other side enforces.
        assert_eq!(MAX_FRAME, 4 * 1024 * 1024);
        assert_eq!(MAX_FRAME, 4_194_304);
    }

    #[test]
    fn error_display_names_each_variant() {
        // A Display impl that stopped writing the reason (empty output) would erase the
        // only diagnostics these framing faults ever carry.
        assert_eq!(Error::Closed.to_string(), "control channel closed");
        assert_eq!(
            Error::Malformed("truncated u16").to_string(),
            "malformed control frame: truncated u16"
        );
        assert_eq!(
            Error::UnknownTag(0x77).to_string(),
            "unknown message tag 0x77"
        );
        assert_eq!(
            Error::Incompatible("unknown framing version").to_string(),
            "incompatible control channel: unknown framing version"
        );
        assert_eq!(
            Error::Io(io::Error::other("disk gone")).to_string(),
            "control i/o: disk gone"
        );
    }

    #[test]
    fn frame_length_cap_is_inclusive_on_both_sides() {
        // A frame of exactly MAX_FRAME bytes is the largest legal one; one byte more is
        // rejected. This pins the boundary the writer and reader must agree on.
        let at_cap = vec![0u8; MAX_FRAME];
        let mut wire = Vec::new();
        write_frame(&mut wire, &at_cap).unwrap();
        assert_eq!(read_frame(&mut &wire[..]).unwrap().len(), MAX_FRAME);

        let over_cap = vec![0u8; MAX_FRAME + 1];
        assert!(matches!(
            write_frame(&mut Vec::new(), &over_cap),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn lists_admit_exactly_max_items() {
        // The item caps are inclusive: a list of exactly MAX_ITEMS must decode, so a
        // `>=` boundary bug that rejected the largest legal list is caught.
        let mut buf = Vec::new();
        put_u16_list(&mut buf, &vec![7u16; MAX_ITEMS as usize]);
        let mut at = 0;
        assert_eq!(
            get_u16_list(&buf, &mut at).unwrap().len(),
            MAX_ITEMS as usize
        );

        let mut buf = Vec::new();
        put_list(&mut buf, &vec![OsString::new(); MAX_ITEMS as usize]);
        let mut at = 0;
        assert_eq!(get_list(&buf, &mut at).unwrap().len(), MAX_ITEMS as usize);

        let mut s = spec();
        s.env = vec![(OsString::new(), OsString::new()); MAX_ITEMS as usize];
        let mut buf = Vec::new();
        put_spec(&mut buf, &s);
        let mut at = 0;
        assert_eq!(
            get_spec(&buf, &mut at).unwrap().env.len(),
            MAX_ITEMS as usize
        );
    }

    /// A reader whose peer sent `sent` and then stalled forever, with a read timeout set —
    /// exactly the guardian's socketpair end.
    #[cfg(unix)]
    fn stalled_peer(sent: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;
        let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_millis(150)))
            .unwrap();
        writer.write_all(sent).unwrap();
        writer.flush().unwrap();
        let frame = read_frame(&mut reader);
        drop(writer); // keep the peer alive across the read, then release it
        frame
    }

    #[cfg(unix)]
    #[test]
    fn a_peer_that_stalls_mid_frame_is_malformed_not_a_wedge() {
        // One byte makes the channel readable, so the reader commits to a frame — and then
        // the peer says nothing more. This must return, not block the guardian's only
        // thread forever (which would strand its shutdown signal, crash check, and
        // readiness deadline while it still owns the application).
        assert!(
            matches!(stalled_peer(&[0x00]), Err(Error::Malformed(_))),
            "a truncated length prefix is a desynced stream, not an idle channel"
        );
        // The same for a complete length prefix whose body never arrives.
        assert!(matches!(
            stalled_peer(&[0x00, 0x00, 0x00, 0x08, 0x01]),
            Err(Error::Malformed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_idle_channel_is_a_retryable_io_condition() {
        // Nothing sent at all: the channel is merely quiet and still frame-aligned, so the
        // reader must not mistake it for a protocol violation and tear the supervisor down.
        assert!(matches!(stalled_peer(&[]), Err(Error::Io(_))));
    }

    #[test]
    fn strings_admit_exactly_max_units() {
        // String caps are inclusive too, counted in native units (bytes on Unix,
        // UTF-16 code units on Windows).
        let big = "a".repeat(MAX_STR_UNITS as usize);

        let mut buf = Vec::new();
        put_str(&mut buf, &big);
        let mut at = 0;
        assert_eq!(get_str(&buf, &mut at).unwrap(), big);

        let mut buf = Vec::new();
        put_os(&mut buf, OsStr::new(&big));
        let mut at = 0;
        assert_eq!(get_os(&buf, &mut at).unwrap(), OsString::from(&big));
    }
}
