#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Update-unaware HTTP fixture used by the updater end-to-end tests.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Socket, Type};

static VERSION: OnceLock<String> = OnceLock::new();
static ARTIFACT: OnceLock<&'static str> = OnceLock::new();
static FAULT: OnceLock<Fault> = OnceLock::new();
static HEALTH_REQUESTS: AtomicUsize = AtomicUsize::new(0);

/// Deterministic bad-application behaviors used by the updater E2E suite. Keeping these in the
/// workload itself (rather than mocking a health probe) exercises the real signed bundle, the
/// release's own reconciler, network timeouts, health, rollback, confirmation, and restart paths.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    ExitBeforeBind,
    Unhealthy,
    HangHealth,
    Flapping,
    CrashOnHealth,
    DegradeAfterReady,
}

impl Fault {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "exit-before-bind" => Ok(Self::ExitBeforeBind),
            "unhealthy" => Ok(Self::Unhealthy),
            "hang-health" => Ok(Self::HangHealth),
            "flapping" => Ok(Self::Flapping),
            "crash-on-health" => Ok(Self::CrashOnHealth),
            "degrade-after-ready" => Ok(Self::DegradeAfterReady),
            other => Err(format!("unknown --fault mode {other:?}")),
        }
    }
}

/// Wait for the hook's durable reap handle to name this process. The record is the only thing that
/// can ever stop this workload — it lives outside every process tree the node stack owns — so
/// serving before it exists would create an unreapable listener.
fn await_record(path: &str) -> bool {
    let me = std::process::id();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(path).is_ok_and(|recorded| {
            recorded
                .split(|c: char| !c.is_ascii_digit())
                .any(|field| field.parse::<u32>() == Ok(me))
        }) {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}

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

pub fn run() {
    run_artifact("sampleapp");
}

/// Run the fixture under a distinct application identity.  The Kind and macOS
/// fuzzers use this to prove that an update replaced the artifact, rather than
/// merely rewriting the version file beside the same executable.
pub fn run_artifact(artifact: &'static str) {
    let loaded = load_version().unwrap_or_else(|error| {
        eprintln!("sampleapp: {error}");
        std::process::exit(2);
    });
    VERSION.set(loaded).expect("version set once");
    ARTIFACT.set(artifact).expect("artifact set once");
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `<flag> <value>`, the only form anything launches this fixture with.
    let flag = |name: &str| {
        args.iter()
            .position(|arg| arg == name)
            .and_then(|at| args.get(at + 1).cloned())
    };
    let fault = flag("--fault")
        .map(|value| Fault::parse(&value))
        .transpose()
        .unwrap_or_else(|error| {
            eprintln!("sampleapp: {error}");
            std::process::exit(2);
        })
        .unwrap_or_default();
    FAULT.set(fault).expect("fault set once");
    // Ahead of every path that could bind, including the injected faults: a workload nothing has
    // recorded is a workload nothing can reap, and the hook that starts one can be killed at any
    // instant between the spawn and the write. Refusing to serve until the record names THIS pid
    // makes that window harmless — the orphan exits on its own bound without ever taking traffic.
    let record = flag("--await-record").unwrap_or_else(|| {
        eprintln!("sampleapp: --await-record <path> is required");
        std::process::exit(2);
    });
    if !await_record(&record) {
        eprintln!(
            "sampleapp {}: no record named pid {} within the bound; exiting without binding",
            version(),
            std::process::id()
        );
        std::process::exit(3);
    }
    if fault == Fault::ExitBeforeBind {
        eprintln!("sampleapp {}: injected exit before bind", version());
        std::process::exit(17);
    }
    let addr = flag("--addr").unwrap_or_else(|| "127.0.0.1:9090".into());
    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sampleapp: invalid --addr {addr:?}: {e}");
            std::process::exit(2);
        }
    };
    let listener = match acquire_listener(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sampleapp: failed to bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "{} {} listening on http://{addr} (pid {})",
        ARTIFACT.get().expect("artifact initialized"),
        version(),
        std::process::id(),
    );

    // Nonblocking accept with a short sleep on `WouldBlock`, so the loop stays responsive
    // to process shutdown instead of blocking indefinitely inside `accept`.
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("sampleapp: set_nonblocking: {e}");
        std::process::exit(1);
    }
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Accepted sockets inherit the listener's non-blocking flag on
                // BSD/macOS; force blocking so the request read waits for the bytes
                // instead of racing them (a short read would look like a bad request).
                let _ = stream.set_nonblocking(false);
                thread::spawn(move || {
                    handle(stream);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => eprintln!("sampleapp: accept error: {e}"),
        }
    }
}

/// Bind a fresh listening socket, reusing a lingering TIME_WAIT address on Unix.
///
/// `SO_REUSEADDR` means two different things. On Unix it only lets a new listener take an address
/// left in `TIME_WAIT` — what a fast restart needs. On Windows it lets a SECOND process bind an
/// address another process is actively listening on, and the newer bind silently steals traffic:
/// exactly the confusion a restart test is trying to detect, converted into a passing run. So it is
/// set on Unix only; on Windows the default (exclusive) bind is the correct behaviour, and a real
/// conflict surfaces as the bind error it is.
fn acquire_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn handle(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split_whitespace().nth(1).unwrap_or("/");

    // Optional diagnostics for deployment smoke tests (not an application contract): the
    // reconciler that owns this process records the PID it spawned and never depends on this
    // endpoint.
    let pid = std::process::id().to_string();
    let secret = std::env::var("DATABASE_PASSWORD").unwrap_or_else(|_| "<missing>".into());
    let fault = *FAULT.get().expect("fault initialized");
    let health_request = path == "/healthz";
    let health_attempt = health_request.then(|| HEALTH_REQUESTS.fetch_add(1, Ordering::SeqCst));
    if health_request && fault == Fault::HangHealth {
        // Deliberately much longer than every probe deadline. This models a wedged handler that
        // accepts the connection and never completes; recovery must not depend on the workload
        // releasing it.
        thread::sleep(Duration::from_secs(300));
    }
    let injected_unhealthy = health_request && matches!(fault, Fault::Unhealthy)
        || health_attempt.is_some_and(|attempt| {
            (fault == Fault::Flapping && attempt % 2 == 1)
                || (fault == Fault::DegradeAfterReady && attempt > 0)
        });
    let crash = path == "/crash" || (health_request && fault == Fault::CrashOnHealth);
    let (code, body) = match path {
        "/version" => (200, version()),
        "/artifact" => (200, *ARTIFACT.get().expect("artifact initialized")),
        "/healthz" if injected_unhealthy => (503, "unhealthy"),
        "/healthz" => (200, "ok"),
        "/pid" => (200, pid.as_str()),
        "/test-secret" => (200, secret.as_str()),
        "/crash" => (200, "crashing"),
        "/" => (200, if version() == "2.0.0" { "green" } else { "red" }),
        _ => (404, "not found"),
    };
    let reason = match code {
        200 => "OK",
        503 => "Service Unavailable",
        _ => "Not Found",
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
    if crash {
        eprintln!("sampleapp {}: explicitly triggered test crash", version());
        std::process::exit(1);
    }
}
