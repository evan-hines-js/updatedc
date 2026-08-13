//! Versioned launcher⇄agent control protocol. The std-only crate is shared by
//! both processes so framing and compatibility rules cannot drift.
//!
//! ## Framing (the hard-to-change layer)
//!
//! Every channel opens with [`MAGIC`] and [`FRAMING_VERSION`]. Each message is
//! `[u32 length BE][u8 tag][body]`, with `length` capped at [`MAX_FRAME`] and every
//! string length-prefixed and bounded.
//!
//! ## Negotiation (the extensible layer)
//!
//! The launcher sends [`Hello`]; the agent requires a shared protocol major and
//! fails closed without one. That is the whole of it — every operation in a given major
//! is mandatory, so there is no second, per-feature negotiation to disagree with it.
//! Skew *inside* a major is additive only: a request tag the peer has never heard of is
//! answered [`Response::Unsupported`] rather than negotiated away in advance.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Identifies an `updated` launcher control channel. Fixed forever.
pub const MAGIC: [u8; 4] = *b"UGRD";
/// Version of the framing layer itself (length-prefix + preamble rules).
pub const FRAMING_VERSION: u8 = 1;

/// Where a node's `config.toml` lives — the one canonical location, defined here rather than
/// restated by each deployment adapter.
///
/// A node's entire local configuration is this single file, so its location is part of the node
/// contract rather than a per-deployment choice: an installer places it here, a lifecycle owner
/// needs no argument to find it, and a co-resident process that must learn which fleet node it is
/// running on has exactly one place to look. `--config` still exists for a non-standard
/// layout, but nothing standard should need it.
///
/// Deliberately outside the writable state directory: the config is installer-owned and read-only,
/// one of the two things that must never be forged.
#[cfg(not(windows))]
pub const DEFAULT_CONFIG: &str = "/etc/updated/config.toml";
#[cfg(windows)]
pub const DEFAULT_CONFIG: &str = r"C:\Program Files\updated\config.toml";

/// The inherited control-channel endpoint: a file-descriptor number on Unix, a handle
/// value on Windows.
pub const CONTROL_ENV: &str = "UPDATED_CONTROL";
/// Hex of the nonce the agent must echo in [`Request::Ready`] to prove *this*
/// launch reached readiness.
pub const READY_NONCE_ENV: &str = "UPDATED_READY_NONCE";
/// The launcher's state directory, so the agent knows where to stage a
/// replacement agent binary (`<state>/agents/<id>/`).
pub const STATE_DIR_ENV: &str = "UPDATED_STATE_DIR";

/// Filename, under the state directory, into which the launcher writes the path of a
/// replacement agent that failed its readiness gate (so the launcher rolled the
/// `desired-agent` pointer back). The agent reads it on recovery and records
/// the *rejection* — the launcher keeps no rejection set of its own, only this one dumb
/// marker; deciding what it means is the agent's job.
pub const REJECTED_AGENT_FILE: &str = "rejected-agent";

/// Filename, under the state directory, holding the path of the COMMITTED agent binary — the
/// one the launcher launches, and the one it rolls back to when a candidate fails its readiness
/// gate. Shared durable layout, not a wire message: the launcher moves this pointer, and the
/// agent must read it (its staging-cache GC has to know which content-addressed directory is
/// the launcher's rollback target, or it can delete the binary the launcher is about to need).
pub const DESIRED_AGENT_FILE: &str = "desired-agent";

/// First line of an agent pointer file, naming the frozen format of the rest.
const AGENT_POINTER_HEADER: &str = "agent-v1";

/// Encode an agent pointer file's contents. The path must be valid UTF-8 (state-dir paths are
/// checked for that at startup), so the record stays plain text.
pub fn encode_agent_pointer(target: &Path) -> io::Result<String> {
    let target = target
        .to_str()
        .ok_or_else(|| io::Error::other("agent path is not valid UTF-8"))?;
    Ok(format!("{AGENT_POINTER_HEADER}\n{target}\n"))
}

/// Decode an agent pointer file's contents, refusing anything that is not exactly the header
/// line followed by one non-empty path.
fn decode_agent_pointer(text: &str) -> io::Result<PathBuf> {
    let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message.to_string());
    let mut lines = text.lines();
    if lines.next() != Some(AGENT_POINTER_HEADER) {
        return Err(invalid("invalid agent pointer header"));
    }
    let path = lines
        .next()
        .ok_or_else(|| invalid("agent pointer path is missing"))?;
    if path.is_empty() || lines.next().is_some() {
        return Err(invalid("agent pointer record is malformed"));
    }
    Ok(PathBuf::from(path))
}

/// Read an agent pointer file, or `None` when it does not exist yet.
pub fn read_agent_pointer(path: &Path) -> io::Result<Option<PathBuf>> {
    match std::fs::read_to_string(path) {
        Ok(text) => decode_agent_pointer(&text).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The protocol major this build implements.
pub const PROTOCOL_MAJOR: u16 = 1;

/// Maximum framed message size. A replacement-agent path is the largest message and is
/// comfortably under this; the cap only bounds a malformed peer.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
const MAX_STR_UNITS: u32 = 1 << 20;

/// An agent readiness nonce: 16 random bytes minted per agent launch and
/// echoed in [`Request::Ready`], correlating readiness with the exact candidate.
pub type Nonce = [u8; 16];

const TAG_REPLACE: u8 = 0x03;
const TAG_READY: u8 = 0x04;

const TAG_OK: u8 = 0x81;
const TAG_ERROR: u8 = 0x82;
const TAG_UNSUPPORTED: u8 = 0x84;

/// The launcher's opening message: the protocol major it speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub major: u16,
}

impl Hello {
    /// The current build's advertisement (launcher side).
    pub fn current() -> Hello {
        Hello {
            major: PROTOCOL_MAJOR,
        }
    }

    /// Write the fixed preamble followed by this hello (launcher side).
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&[FRAMING_VERSION])?;
        let mut body = Vec::new();
        put_u16(&mut body, self.major);
        write_frame(w, &body)?;
        Ok(())
    }

    /// Read and validate the preamble, then the hello (agent side).
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
        let major = get_u16(&body, &mut at)?;
        end_of_frame(&body, at)?;
        Ok(Hello { major })
    }

    /// Whether this build can talk to the peer that sent this hello. Equality on one constant,
    /// fail-closed: there is exactly one protocol major, every operation in it is mandatory, and
    /// the launcher and the agent are shipped and updated as one pair — a build that meets a
    /// different major refuses to proceed rather than guessing which half of the protocol it
    /// shares. This is the ONE compatibility decision in the protocol.
    pub fn compatible(&self) -> bool {
        self.major == PROTOCOL_MAJOR
    }
}

/// What the agent can ask the launcher to do. The launcher manages exactly one thing —
/// which agent binary runs — so the protocol carries agent-candidate operations and
/// nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Hand off to the staged replacement agent at this opaque path.
    ReplaceAgent(OsString),
    /// This agent has initialized; the nonce proves it is *this* launch.
    Ready(Nonce),
}

/// The launcher's reply to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The request succeeded.
    Ok,
    /// The request failed; the string is a human-readable reason (diagnostics only).
    Error(String),
    /// The launcher does not implement the requested operation.
    Unsupported,
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
    // stops would block a single-threaded reader inside `read_exact` forever — the launcher
    // would stop servicing its shutdown signal and its readiness deadline.
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

/// Every writer below enforces exactly the bound its reader rejects on. Asymmetry here is
/// not a missing nicety: an over-long string still fits in a legal sub-[`MAX_FRAME`]
/// frame, so it would encode fine and the peer would answer `Malformed` — which the
/// launcher's serve loop reads as a channel fault, stopping and relaunching a healthy
/// agent that then sends the same message again, forever. Refusing at encode time
/// turns that loop into one bounded local error.
fn put_os(out: &mut Vec<u8>, s: &OsStr) -> Result<()> {
    let (unit_count, bytes) = os_units(s);
    if unit_count > MAX_STR_UNITS {
        return Err(Error::Malformed("string exceeds MAX_STR_UNITS"));
    }
    put_u32(out, unit_count);
    out.extend_from_slice(&bytes);
    Ok(())
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

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<()> {
    if s.len() as u64 > MAX_STR_UNITS as u64 {
        return Err(Error::Malformed("string exceeds MAX_STR_UNITS"));
    }
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
    Ok(())
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

// ── message encode/decode ────────────────────────────────────────────────────────

/// Every decoder ends here: a frame that carries a byte more than its message needs is malformed,
/// not tolerable. There is one protocol major and one shipped pair, so trailing bytes are never a
/// newer peer's optional field — they are a truncation, a desync, or a peer writing a message this
/// build cannot mean. The same rule the signed contracts apply with `deny_unknown_fields`.
fn end_of_frame(body: &[u8], at: usize) -> Result<()> {
    if at == body.len() {
        Ok(())
    } else {
        Err(Error::Malformed("trailing bytes after message"))
    }
}

impl Request {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Request::ReplaceAgent(path) => {
                out.push(TAG_REPLACE);
                put_os(&mut out, path)?;
            }
            Request::Ready(nonce) => {
                out.push(TAG_READY);
                out.extend_from_slice(nonce);
            }
        }
        Ok(out)
    }

    fn decode(buf: &[u8]) -> Result<Request> {
        let (&tag, body) = buf.split_first().ok_or(Error::Malformed("empty frame"))?;
        let mut at = 0usize;
        let req = match tag {
            TAG_REPLACE => Request::ReplaceAgent(get_os(body, &mut at)?),
            TAG_READY => Request::Ready(get_nonce(body, &mut at)?),
            other => return Err(Error::UnknownTag(other)),
        };
        end_of_frame(body, at)?;
        Ok(req)
    }

    /// Write this request as one frame (agent side). Fails without writing anything
    /// if the message violates a wire bound the reader would reject.
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        write_frame(w, &self.encode()?)
    }

    /// Read one request frame (launcher side). `Err(UnknownTag)` on an operation this
    /// build does not know — the launcher answers [`Response::Unsupported`].
    pub fn read(r: &mut impl Read) -> Result<Request> {
        Request::decode(&read_frame(r)?)
    }
}

impl Response {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            Response::Ok => out.push(TAG_OK),
            Response::Error(msg) => {
                out.push(TAG_ERROR);
                put_str(&mut out, msg)?;
            }
            Response::Unsupported => out.push(TAG_UNSUPPORTED),
        }
        Ok(out)
    }

    fn decode(buf: &[u8]) -> Result<Response> {
        let (&tag, body) = buf.split_first().ok_or(Error::Malformed("empty frame"))?;
        let mut at = 0usize;
        let resp = match tag {
            TAG_OK => Response::Ok,
            TAG_ERROR => Response::Error(get_str(body, &mut at)?),
            TAG_UNSUPPORTED => Response::Unsupported,
            other => return Err(Error::UnknownTag(other)),
        };
        end_of_frame(body, at)?;
        Ok(resp)
    }

    /// Write this response as one frame (launcher side). Fails without writing anything
    /// if the message violates a wire bound the reader would reject.
    pub fn write(&self, w: &mut impl Write) -> Result<()> {
        write_frame(w, &self.encode()?)
    }

    /// Read one response frame (agent side).
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
        round_trip_request(Request::ReplaceAgent(OsString::from(
            "/var/lib/app/agents/deadbeef/agent",
        )));
        round_trip_request(Request::Ready([0xABu8; 16]));
    }

    #[test]
    fn responses_round_trip() {
        round_trip_response(Response::Ok);
        round_trip_response(Response::Error("could not stage: ENOENT".into()));
        round_trip_response(Response::Unsupported);
    }

    #[test]
    fn the_handshake_round_trips_and_admits_only_this_build_s_major() {
        let mut wire = Vec::new();
        Hello::current().write(&mut wire).unwrap();
        let hello = Hello::read(&mut &wire[..]).unwrap();
        assert_eq!(hello, Hello::current());
        assert!(hello.compatible());
        // Any other major fails closed: one major exists, and every operation in it is mandatory.
        assert!(!Hello {
            major: PROTOCOL_MAJOR + 1
        }
        .compatible());
        assert!(!Hello { major: 0 }.compatible());
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
    fn unknown_tag_surfaces_so_the_launcher_can_answer_unsupported() {
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
        framed.push(TAG_READY);
        assert!(matches!(
            Request::read(&mut &framed[..]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn clean_eof_at_a_boundary_is_closed_not_error() {
        let empty: &[u8] = &[];
        assert!(matches!(Request::read(&mut &empty[..]), Err(Error::Closed)));
    }

    #[test]
    fn a_frame_with_trailing_bytes_is_malformed() {
        // Nothing is deployed and there is one protocol major, so a byte past the end of a message
        // is never a newer peer's optional field: it is a desync or a peer writing something this
        // build cannot mean. Both decoders refuse it, the same rule `deny_unknown_fields` applies
        // to the signed contracts — one answer to unknown trailing data, not two.
        let mut body = Request::Ready([7u8; 16]).encode().unwrap();
        body.push(0xff);
        assert!(matches!(
            Request::decode(&body),
            Err(Error::Malformed("trailing bytes after message"))
        ));

        let mut body = Response::Ok.encode().unwrap();
        body.push(0);
        assert!(matches!(
            Response::decode(&body),
            Err(Error::Malformed("trailing bytes after message"))
        ));

        // Including the handshake, where a tolerant reader would have silently accepted a peer
        // offering a list of majors this build does not have the machinery to choose among.
        let mut wire = MAGIC.to_vec();
        wire.push(FRAMING_VERSION);
        write_frame(&mut wire, &[0, PROTOCOL_MAJOR as u8, 0, 2]).unwrap();
        assert!(matches!(
            Hello::read(&mut &wire[..]),
            Err(Error::Malformed("trailing bytes after message"))
        ));
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
    fn a_writer_refuses_exactly_what_the_reader_would_reject() {
        // An asymmetric bound is not a cosmetic problem: an over-long string still fits in a
        // legal frame, so it would encode, and the launcher would read it as Malformed — a
        // channel fault, which stops and relaunches a healthy agent that then sends the
        // identical message again. The write must fail locally instead.
        let over = OsString::from("a".repeat(MAX_STR_UNITS as usize + 1));
        assert!(matches!(
            Request::ReplaceAgent(over).write(&mut Vec::new()),
            Err(Error::Malformed(_))
        ));

        assert!(matches!(
            Response::Error("e".repeat(MAX_STR_UNITS as usize + 1)).write(&mut Vec::new()),
            Err(Error::Malformed(_))
        ));
    }

    /// A reader whose peer sent `sent` and then stalled forever, with a read timeout set —
    /// exactly the launcher's socketpair end.
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
        // the peer says nothing more. This must return, not block the launcher's only
        // thread forever (which would strand its shutdown signal and readiness deadline).
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
        // reader must not mistake it for a protocol violation and tear the agent down.
        assert!(matches!(stalled_peer(&[]), Err(Error::Io(_))));
    }

    #[test]
    fn strings_admit_exactly_max_units() {
        // String caps are inclusive, counted in native units (bytes on Unix,
        // UTF-16 code units on Windows).
        let big = "a".repeat(MAX_STR_UNITS as usize);

        let mut buf = Vec::new();
        put_str(&mut buf, &big).unwrap();
        let mut at = 0;
        assert_eq!(get_str(&buf, &mut at).unwrap(), big);

        let mut buf = Vec::new();
        put_os(&mut buf, OsStr::new(&big)).unwrap();
        let mut at = 0;
        assert_eq!(get_os(&buf, &mut at).unwrap(), OsString::from(&big));
    }
}
