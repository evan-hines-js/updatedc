//! Update-unaware HTTP fixture. `restart` works on every OS; Unix `reexec` drains
//! requests and replaces the process image while preserving its PID and socket.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
#[cfg(unix)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Socket, Type};

static VERSION: OnceLock<String> = OnceLock::new();

fn version() -> &'static str {
    VERSION.get().expect("version initialized")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseConfig {
    version: String,
}

fn load_version() -> Result<String, String> {
    let raw = std::fs::read_to_string("config/release.toml")
        .map_err(|e| format!("reading config/release.toml: {e}"))?;
    let config: ReleaseConfig =
        toml::from_str(&raw).map_err(|e| format!("parsing config/release.toml: {e}"))?;
    if config.version.trim().is_empty() {
        return Err("release version is empty".into());
    }
    Ok(config.version)
}

/// Set when the listening socket is inherited across the reexec, so the fresh
/// instance keeps serving the very same socket with no dropped connections.
#[cfg(unix)]
const LISTEN_FD_ENV: &str = "SAMPLEAPP_LISTEN_FD";

/// Raised by the reload-signal handler; the accept loop performs the reload so we
/// never re-exec from async-signal context.
#[cfg(unix)]
static RELOAD: AtomicBool = AtomicBool::new(false);
/// In-flight request count, so a reload drains outstanding responses before the
/// exec replaces this image.
static INFLIGHT: AtomicUsize = AtomicUsize::new(0);

pub fn run(reexec_capable: bool) {
    let loaded = load_version().unwrap_or_else(|error| {
        eprintln!("sampleapp: {error}");
        std::process::exit(2);
    });
    VERSION.set(loaded).expect("version set once");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = flag(&args, "--addr").unwrap_or_else(|| "127.0.0.1:9090".into());
    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sampleapp: invalid --addr {addr:?}: {e}");
            std::process::exit(2);
        }
    };
    let mode = flag(&args, "--reload-mode").unwrap_or_else(|| "restart".into());
    if mode == "reexec" && !reexec_capable {
        eprintln!("sampleapp: reexec mode requires the sampleapp-reexec fixture");
        std::process::exit(2);
    }

    let listener = match acquire_listener(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sampleapp: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    #[cfg(unix)]
    let reload_sig = flag(&args, "--reload-signal").unwrap_or_else(|| "HUP".into());
    #[cfg(unix)]
    install_reload_handler(reload_signal(&reload_sig));

    eprintln!(
        "sampleapp {} listening on http://{addr} (pid {}, mode {mode})",
        version(),
        std::process::id()
    );

    // Test hook: a release that passes its health check and then dies. When this
    // build's version matches `--crash-version`, exit after `--crash-after-ms`
    // (default 5s) — long enough to pass the health gate — to exercise the
    // supervisor's post-commit unconfirmed-update revert. No effect on other versions.
    if flag(&args, "--crash-version").as_deref() == Some(version()) {
        let after = flag(&args, "--crash-after-ms")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(after));
            eprintln!(
                "sampleapp {}: simulated post-health crash after {after}ms",
                version()
            );
            std::process::exit(1);
        });
    }

    // Nonblocking accept so the loop can act on a pending reload signal promptly.
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("sampleapp: set_nonblocking: {e}");
        std::process::exit(1);
    }
    loop {
        #[cfg(unix)]
        if RELOAD.swap(false, Ordering::SeqCst) {
            reload(&mode, &listener, &args);
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets inherit the listener's non-blocking flag on
                // BSD/macOS; force blocking so the request read waits for the bytes
                // instead of racing them (a short read would look like a bad request).
                let _ = stream.set_nonblocking(false);
                INFLIGHT.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    handle(stream);
                    INFLIGHT.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => eprintln!("sampleapp: accept error: {e}"),
        }
    }
}

/// Inherit the listening socket from a predecessor (LISTEN_FD, set before the
/// reexec) or bind a fresh one with SO_REUSEADDR.
fn acquire_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    #[cfg(unix)]
    if let Ok(v) = std::env::var(LISTEN_FD_ENV) {
        use std::os::unix::io::FromRawFd;
        let fd: i32 = v
            .parse()
            .map_err(|_| std::io::Error::other(format!("bad {LISTEN_FD_ENV}={v:?}")))?;
        // Safety: the fd was handed to us across exec by our predecessor and refers
        // to a bound, listening TCP socket.
        return Ok(unsafe { TcpListener::from_raw_fd(fd) });
    }
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    // A deep backlog absorbs the brief no-accept window while a reexec drains and
    // re-execs, so connections arriving then wait in the queue rather than being
    // refused — keeping a reload at zero dropped requests.
    socket.listen(1024)?;
    Ok(socket.into())
}

fn handle(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");

    // Optional diagnostics for deployment smoke tests (not an application contract):
    // guardian ownership and adoption use the OS-derived child PID over `control` and
    // never depend on this endpoint.
    let pid = std::process::id().to_string();
    let (code, body) = match path {
        "/version" => (200, version()),
        "/healthz" => (200, "ok"),
        "/pid" => (200, pid.as_str()),
        _ => (404, "not found"),
    };
    let reason = if code == 200 { "OK" } else { "Not Found" };
    let health_headers = if path == "/healthz" {
        let token = std::env::var(updated::env::HEALTH_TOKEN)
            .map(|v| format!("{}: {v}\r\n", updated::health::TOKEN_HEADER))
            .unwrap_or_default();
        format!(
            "{token}{}: {}\r\n",
            updated::health::VERSION_HEADER,
            version()
        )
    } else {
        String::new()
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n{health_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

/// Map a signal name to its number. Different servers reload on different signals
/// (nginx binary-upgrade uses `USR2`); the operator's `--reload-command` sends
/// whichever one this app listens for.
#[cfg(unix)]
fn reload_signal(name: &str) -> libc::c_int {
    match name.trim().to_ascii_uppercase().as_str() {
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        _ => libc::SIGHUP,
    }
}

#[cfg(unix)]
fn install_reload_handler(sig: libc::c_int) {
    // Safety: the handler only stores to an atomic — async-signal-safe.
    let handler = on_reload as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(sig, handler);
    }
}

#[cfg(unix)]
extern "C" fn on_reload(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn reload(mode: &str, listener: &TcpListener, args: &[String]) {
    if mode == "reexec" {
        reexec(listener, args);
    }
    // `restart` mode ignores the reload signal.
}

/// Same-PID upgrade: drain in-flight requests, then keep the socket across an
/// in-place exec of the active bundle entrypoint. Never returns on success.
#[cfg(unix)]
fn reexec(listener: &TcpListener, args: &[String]) {
    let fd = keep_across_exec(listener);
    // Safety: we set env then immediately exec; no other thread reads it.
    unsafe {
        std::env::set_var(LISTEN_FD_ENV, fd.to_string());
    }
    // We stopped accepting when we left the loop, so let in-flight responses finish
    // before exec replaces this image (execv would otherwise kill their threads
    // mid-write). New connections wait in the inherited listen backlog.
    drain();
    let err = exec_active(args);
    eprintln!("sampleapp: reexec failed: {err}");
    // A failed exec has not replaced this process. Keep the old image accepting
    // connections; its version proof will make the supervisor reject the candidate,
    // restore the predecessor pointer, and signal us again through the same path.
    unsafe {
        std::env::remove_var(LISTEN_FD_ENV);
    }
}

/// Clear FD_CLOEXEC so the listening socket survives an exec, and return its fd.
#[cfg(unix)]
fn keep_across_exec(listener: &TcpListener) -> i32 {
    use std::os::unix::io::AsRawFd;
    let fd = listener.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
        }
    }
    fd
}

/// Replace this process image with the binary at `self_path`, preserving argv and
/// the current environment (including LISTEN_FD_ENV). Returns only on failure.
#[cfg(unix)]
fn exec_active(args: &[String]) -> std::io::Error {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let root = match std::env::var(updated::env::INSTALL_ROOT) {
        Ok(root) => std::path::PathBuf::from(root),
        Err(error) => return std::io::Error::other(format!("missing install root: {error}")),
    };
    let release = match updated::bundle::read_active(&root.join("active-release")) {
        Ok(Some(release)) => release,
        Ok(None) => return std::io::Error::other("active release is missing"),
        Err(error) => return error,
    };
    // Trust the committed tree (verified once at ingest) and resolve its entrypoint through
    // the same default provider the tower uses — no full re-hash on every reload.
    let launch =
        match updated::provider::BundleStore::new(root.join("versions"), root.join("staging"))
            .resolve(&release)
        {
            Ok(found) => found,
            Err(error) => return error,
        };
    let entrypoint = launch.program;
    let release_dir = launch.cwd;
    let previous_dir = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => return error,
    };
    if let Err(error) = std::env::set_current_dir(&release_dir) {
        return error;
    }
    let program = match CString::new(entrypoint.as_os_str().as_bytes()) {
        Ok(program) => program,
        Err(_) => {
            let _ = std::env::set_current_dir(previous_dir);
            return std::io::Error::other("entrypoint contains a NUL byte");
        }
    };
    let mut owned = Vec::with_capacity(args.len().max(1));
    owned.push(program.clone());
    for arg in args {
        match CString::new(arg.as_bytes()) {
            Ok(arg) => owned.push(arg),
            Err(_) => {
                let _ = std::env::set_current_dir(previous_dir);
                return std::io::Error::other("application argument contains a NUL byte");
            }
        }
    }
    let mut argv: Vec<*const libc::c_char> = owned.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());
    // `execv`, unlike `execvp`, never falls back to `/bin/sh` for ENOEXEC. Thus an
    // invalid candidate returns here without replacing the healthy process image.
    unsafe { libc::execv(program.as_ptr(), argv.as_ptr()) };
    let error = std::io::Error::last_os_error();
    let _ = std::env::set_current_dir(previous_dir);
    error
}

/// Wait for outstanding responses to finish (bounded). We only call this after
/// leaving the accept loop, so INFLIGHT only decreases and this converges quickly
/// even under sustained load.
#[cfg(unix)]
fn drain() {
    for _ in 0..500 {
        if INFLIGHT.load(Ordering::SeqCst) == 0 {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}
