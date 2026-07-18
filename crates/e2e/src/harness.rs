//! Cross-platform test harness: workspace paths, `cargo` builds, the release
//! `server` CLI, HTTP polling, and a spawned process whose whole tree is torn
//! down on drop (process group on Unix, Job Object on Windows). Child output is
//! streamed to this process's stderr (so CI shows it inline) and captured in
//! memory for assertions — never written to log files.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Fail the scenario with a message (and a non-zero exit via `main`'s `Result`).
pub type R<T = ()> = Result<T, String>;

pub fn fail<T>(msg: impl Into<String>) -> R<T> {
    Err(msg.into())
}

/// An in-memory capture of a child's combined stdout+stderr, shared with the
/// reader threads that tee it to the console.
pub type LogBuf = Arc<Mutex<String>>;

pub fn log_buf() -> LogBuf {
    Arc::new(Mutex::new(String::new()))
}

pub fn buf_contains(buf: &LogBuf, needle: &str) -> bool {
    buf.lock().unwrap().contains(needle)
}

/// How many times `needle` appears in the captured output — for "exactly once" /
/// "did not loop" assertions.
pub fn buf_count(buf: &LogBuf, needle: &str) -> usize {
    buf.lock().unwrap().matches(needle).count()
}

pub fn wait_for_buf(buf: &LogBuf, needle: &str, secs: u64) -> bool {
    wait_until(secs, || buf_contains(buf, needle))
}

/// Tee a child stream to this process's stderr (prefixed with `label`) and append
/// it to `buf`. Spawns a reader thread that ends when the stream closes.
pub fn tee(label: &str, stream: Option<impl Read + Send + 'static>, buf: &LogBuf) {
    let Some(stream) = stream else { return };
    let (buf, label) = (buf.clone(), label.to_string());
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    eprint!("[{label}] {line}");
                    if let Ok(mut b) = buf.lock() {
                        b.push_str(&line);
                    }
                }
            }
        }
    });
}

/// Shared paths and build outputs for one run.
pub struct Ctx {
    _run_lock: std::fs::File,
    pub root: PathBuf,
    pub work: PathBuf,
    pub server: PathBuf,
    pub supervisor: PathBuf,
    pub bootstrap: PathBuf,
    pub oneshot: PathBuf,
    /// Rust's own OS-arch key, e.g. `macos-aarch64` / `windows-x86_64`; matches
    /// what the supervisor sends and the server keys manifests by.
    pub platkey: String,
    /// `.exe` on Windows, empty elsewhere.
    pub exe: &'static str,
}

impl Ctx {
    pub fn new() -> R<Ctx> {
        // crates/e2e/ -> workspace root.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("cannot locate workspace root")?
            .to_path_buf();
        let work = root.join("target/e2e-work");
        let run_lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(root.join("target/e2e.lock"))
            .map_err(str_err)?;
        let lock_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match run_lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < lock_deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return fail(
                        "another E2E run still owns target/e2e.lock after 10s; stop that run before retrying",
                    );
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return fail(format!(
                        "acquiring the E2E shared ports/workdir lock: {error}"
                    ));
                }
            }
        }
        // An interrupted prior run can leave durable app processes behind (on Unix
        // they outlive their supervisor by design); reap them so they don't hold a
        // port this run needs.
        reap_workdir(&work);
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(work.join("build")).map_err(str_err)?;
        let exe = if cfg!(windows) { ".exe" } else { "" };
        let bin = |name: &str| root.join(format!("target/release/{name}{exe}"));
        Ok(Ctx {
            _run_lock: run_lock,
            server: bin("server"),
            // The canonical chaos-enabled supervisor is copied here by `build()`.
            // Versioned self-update fixture builds reuse Cargo's target path, so no
            // scenario may execute that mutable build output directly.
            supervisor: work.join(format!("build/supervisor-chaos{exe}")),
            bootstrap: bin("bootstrap"),
            oneshot: bin("updated-oneshot"),
            platkey: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            exe,
            work,
            root,
        })
    }

    /// Build the release binaries the harness drives. The supervisor is built with its
    /// `chaos` feature — the crash-injection points the chaos-recovery scenarios need,
    /// which are compiled out of every ordinary build.
    pub fn build(&self) -> R {
        cargo(
            &self.root,
            None,
            &[
                "build",
                "--release",
                "-p",
                "server",
                "-p",
                "bootstrap",
                "-p",
                "updated-oneshot",
            ],
        )?;
        cargo(
            &self.root,
            None,
            &[
                "build",
                "--release",
                "-p",
                "supervisor",
                "--features",
                "chaos",
            ],
        )?;
        let built = self
            .root
            .join(format!("target/release/supervisor{}", self.exe));
        std::fs::copy(built, &self.supervisor).map_err(str_err)?;
        Ok(())
    }

    /// Build one version-agnostic sample binary. Release identity lives in its bundle config.
    pub fn build_app(&self, version: &str) -> R<PathBuf> {
        cargo(&self.root, None, &["build", "--release", "-p", "sampleapp"])?;
        let src = self
            .root
            .join(format!("target/release/sampleapp{}", self.exe));
        let dst = self.work.join(format!("build/app-{version}{}", self.exe));
        std::fs::copy(&src, &dst).map_err(str_err)?;
        Ok(dst)
    }

    pub fn build_reexec_app(&self, version: &str) -> R<PathBuf> {
        cargo(
            &self.root,
            None,
            &["build", "--release", "-p", "sampleapp-reexec"],
        )?;
        let src = self
            .root
            .join(format!("target/release/sampleapp-reexec{}", self.exe));
        let dst = self
            .work
            .join(format!("build/reexec-app-{version}{}", self.exe));
        std::fs::copy(&src, &dst).map_err(str_err)?;
        Ok(dst)
    }

    /// Build `supervisor` with a baked version (so the bytes differ per version) and
    /// copy it to `build/supervisor-<v><exe>`, for the self-update scenarios.
    pub fn build_supervisor(&self, version: &str) -> R<PathBuf> {
        cargo(
            &self.root,
            Some(("SUPERVISOR_VERSION", version)),
            &[
                "build",
                "--release",
                "-p",
                "supervisor",
                "--features",
                "chaos",
            ],
        )?;
        let src = self
            .root
            .join(format!("target/release/supervisor{}", self.exe));
        let dst = self
            .work
            .join(format!("build/supervisor-{version}{}", self.exe));
        std::fs::copy(&src, &dst).map_err(str_err)?;
        Ok(dst)
    }

    /// The update-transaction boundaries the supervisor can crash at, enumerated from the
    /// binary itself (`--list-chaos-boundaries`, a chaos-feature build). One source of
    /// truth: the chaos scenario drives exactly the supervisor's crossings, so a boundary
    /// added or renamed on one side can never silently go untested on the other.
    pub fn chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-chaos-boundaries")
    }

    pub fn rollback_chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-rollback-chaos-boundaries")
    }

    pub fn abort_chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-abort-chaos-boundaries")
    }

    fn list_chaos_boundaries(&self, flag: &str) -> R<Vec<String>> {
        let out = Command::new(&self.supervisor)
            .arg(flag)
            .output()
            .map_err(str_err)?;
        if !out.status.success() {
            return fail(format!(
                "`supervisor {flag}` failed (chaos feature not built?)"
            ));
        }
        let list: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if list.is_empty() {
            return fail("supervisor reported no chaos boundaries");
        }
        Ok(list)
    }

    /// Initialize a TUF repository and its role keys under `dir` (`dir/repo`,
    /// `dir/keys`).
    pub fn init_repo(&self, dir: &Path) -> R {
        run(Command::new(&self.server)
            .arg("init")
            .arg("--repo")
            .arg(dir.join("repo"))
            .arg("--keys")
            .arg(dir.join("keys")))
    }

    /// Publish a per-platform release of `source` for `product` at `version`.
    pub fn publish(&self, dir: &Path, product: &str, version: &str, source: &Path) -> R {
        let application = product != "supervisor";
        let mut command = Command::new(&self.server);
        command
            .arg(if application {
                "publish-app"
            } else {
                "publish-supervisor"
            })
            .arg("--repo")
            .arg(dir.join("repo"))
            .arg("--keys")
            .arg(dir.join("keys"))
            .args(["--product", product, "--version", version])
            .arg(if application { "--bundle" } else { "--target" })
            .arg(format!("{}={}", self.platkey, source.display()));
        if application {
            command
                .arg("--entrypoint")
                .arg(format!("bin/app{}", self.exe));
        }
        run(&mut command)
    }

    /// Serve the TUF repository at `dir/repo`; the returned handle keeps it alive.
    pub fn serve(&self, dir: &Path, addr: &str) -> R<Proc> {
        run(Command::new(&self.server)
            .arg("publish-assignment")
            .arg("--repo")
            .arg(dir.join("repo"))
            .arg("--keys")
            .arg(dir.join("keys"))
            .args(["--name", "assignments/node.json"])
            .args(["--metadata-url", &self.meta_url(addr)])
            .args(["--targets-url", &self.targets_url(addr)]))?;
        Proc::spawn(
            "server",
            Command::new(&self.server)
                .arg("serve")
                .arg("--repo")
                .arg(dir.join("repo"))
                .args(["--addr", addr]),
        )
    }

    /// The installer-pinned root a client trusts for the repo under `dir`.
    pub fn root(&self, dir: &Path) -> PathBuf {
        dir.join("repo/metadata/root.json")
    }
    pub fn meta_url(&self, srv: &str) -> String {
        format!("http://{srv}/metadata/")
    }
    pub fn targets_url(&self, srv: &str) -> String {
        format!("http://{srv}/targets/")
    }
    /// A key file path under `dir/keys` (e.g. `root.pk8`). Only the Unix-only
    /// key-permissions scenario needs it.
    #[cfg(unix)]
    pub fn key(&self, dir: &Path, role: &str) -> PathBuf {
        dir.join(format!("keys/{role}.pk8"))
    }
}

// ------------------------------- HTTP polling -------------------------------

/// Hex SHA-256 of a file — used to seed committed installed-target state. Delegates
/// to the same streaming hasher the tower uses, so the harness and the production
/// path can never disagree on a digest; an unreadable file yields an empty string.
pub fn sha256_hex(path: &Path) -> String {
    updated::hash::sha256_file(path).unwrap_or_default()
}

/// Make an immutable fixture file writable so a test can simulate out-of-band tampering.
pub fn make_writable(path: &Path) -> R {
    let mut permissions = std::fs::metadata(path).map_err(str_err)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(windows)]
    // This API is dangerous on Unix because it can grant write access broadly;
    // this branch only exists on Windows, where clearing FILE_ATTRIBUTE_READONLY
    // is exactly the operation the tampering fixture requires.
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions).map_err(str_err)
}

/// GET `url`, returning the body on a 2xx response.
pub fn http_text(url: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build();
    agent.get(url).call().ok()?.into_string().ok()
}

/// Poll until `GET http://<addr>/version` equals `want`.
pub fn wait_for_version(addr: &str, want: &str, secs: u64) -> bool {
    wait_until(secs, || {
        http_text(&format!("http://{addr}/version")).as_deref() == Some(want)
    })
}

pub fn wait_until(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    cond()
}

// -------------------------- process tree management -------------------------

/// A spawned process whose entire descendant tree is stopped on drop. Its output
/// is teed to the console and captured in `log`.
pub struct Proc {
    child: Child,
    log: LogBuf,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

/// One log-query API for directly spawned processes and init-model services.
pub trait CapturedLog {
    fn log_buffer(&self) -> &LogBuf;

    fn log_contains(&self, needle: &str) -> bool {
        buf_contains(self.log_buffer(), needle)
    }

    fn wait_for_log(&self, needle: &str, secs: u64) -> bool {
        wait_for_buf(self.log_buffer(), needle, secs)
    }

    fn captured_log(&self) -> String {
        self.log_buffer()
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }
}

impl CapturedLog for Proc {
    fn log_buffer(&self) -> &LogBuf {
        &self.log
    }
}

impl Proc {
    /// Spawn `cmd` in its own process group (Unix) / Job Object (Windows) so it
    /// can be torn down as a unit, teeing its stdout+stderr to the console and an
    /// in-memory buffer.
    pub fn spawn(label: &str, cmd: &mut Command) -> R<Proc> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;
            cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn {label}: {e}"))?;
        let log = log_buf();
        tee(label, child.stdout.take(), &log);
        tee(label, child.stderr.take(), &log);
        #[cfg(windows)]
        let job = assign_job(&child)?;
        Ok(Proc {
            child,
            log,
            #[cfg(windows)]
            job,
        })
    }

    pub fn log_count(&self, needle: &str) -> usize {
        buf_count(&self.log, needle)
    }

    pub fn has_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// This process's own PID (e.g. the guardian's), so a test can signal it directly.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Kill just this process (not its whole group / job) and reap it, simulating
    /// a supervisor crash while its managed child keeps running. On Unix the child
    /// is in its own process group; on Windows it survives while this `Proc`'s job
    /// handle is still open (its kill-on-close fires only when this `Proc` drops).
    pub fn kill_main(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            let pgid = self.child.id() as libc::pid_t;
            libc::kill(-pgid, libc::SIGTERM);
            std::thread::sleep(Duration::from_millis(400));
            libc::kill(-pgid, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
fn assign_job(child: &Child) -> R<windows_sys::Win32::Foundation::HANDLE> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return fail("CreateJobObjectW failed");
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        AssignProcessToJobObject(job, child.as_raw_handle() as _);
        Ok(job)
    }
}

// ------------------------------ init-system model ---------------------------

/// A process run under a *simulated init system*. Like systemd `Restart=on-failure`, it
/// relaunches the process whenever it exits, up to a start-limit burst, then gives up.
///
/// The transparent guardian rolls a crash up and exits, delegating the restart to the
/// init system; production runs it under systemd / a Windows service. The harness has no
/// such supervisor, so recovery paths (rollback before commit or reverting an
/// unconfirmed update) would never get a second boot to run in. `Service` is that init
/// system. Output across every restart accumulates in one buffer, and `Drop` both stops
/// the restarts and tears down the running instance's whole process tree.
pub struct Service {
    stop: Arc<AtomicBool>,
    log: LogBuf,
    monitor: Option<std::thread::JoinHandle<()>>,
}

impl CapturedLog for Service {
    fn log_buffer(&self) -> &LogBuf {
        &self.log
    }
}

impl Service {
    /// systemd's default `StartLimitBurst`. Enough restarts for recovery to converge
    /// (each revert costs a couple of boots); after it the tower settles and no
    /// more fire, so this is only a runaway backstop.
    const MAX_STARTS: u32 = 12;

    /// Run `cmd` under the init model. The command's program, args, and explicit env are
    /// captured so each restart re-runs an identical process (its state dir and config
    /// persist on disk, so a restart simply re-reads them).
    pub fn spawn(label: &'static str, cmd: &Command) -> Service {
        let program = cmd.get_program().to_os_string();
        let args: Vec<OsString> = cmd.get_args().map(|a| a.to_os_string()).collect();
        let envs: Vec<(OsString, Option<OsString>)> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string())))
            .collect();
        let log = log_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let monitor = std::thread::spawn({
            let (log, stop) = (log.clone(), stop.clone());
            move || run_service(label, &program, &args, &envs, &log, &stop)
        });
        Service {
            stop,
            log,
            monitor: Some(monitor),
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(m) = self.monitor.take() {
            let _ = m.join();
        }
    }
}

/// The monitor loop: (re)launch the captured command until asked to stop or the start
/// limit is hit. On a stop request it tears the current instance's tree down; on a
/// self-exit it reaps and relaunches after a short `RestartSec` pause.
fn run_service(
    label: &'static str,
    program: &OsString,
    args: &[OsString],
    envs: &[(OsString, Option<OsString>)],
    log: &LogBuf,
    stop: &Arc<AtomicBool>,
) {
    let mut starts = 0;
    while !stop.load(Ordering::SeqCst) && starts < Service::MAX_STARTS {
        starts += 1;
        let mut cmd = Command::new(program);
        cmd.args(args);
        for (k, v) in envs {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        let mut grouped = match spawn_grouped(&mut cmd) {
            Ok(g) => g,
            Err(e) => {
                if let Ok(mut b) = log.lock() {
                    b.push_str(&format!("[{label}] service could not spawn: {e}\n"));
                }
                return;
            }
        };
        tee(label, grouped.child.stdout.take(), log);
        tee(label, grouped.child.stderr.take(), log);
        loop {
            if stop.load(Ordering::SeqCst) {
                grouped.teardown();
                let _ = grouped.child.wait();
                return;
            }
            match grouped.child.try_wait() {
                Ok(Some(_)) => break, // exited on its own → the init system restarts it
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        grouped.close();
        let _ = grouped.child.wait();
        std::thread::sleep(Duration::from_millis(200)); // RestartSec
    }
}

/// A spawned child in its own process group (Unix) / Job Object (Windows), so its whole
/// tree can be torn down as a unit — the shared mechanism behind [`Proc`] and [`Service`].
struct Grouped {
    child: Child,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

impl Grouped {
    /// Kill the whole tree (the child self-exited case leaves this to `Drop`).
    fn teardown(&self) {
        #[cfg(unix)]
        unsafe {
            let pgid = self.child.id() as libc::pid_t;
            libc::kill(-pgid, libc::SIGTERM);
            std::thread::sleep(Duration::from_millis(400));
            libc::kill(-pgid, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
    /// Release the OS handle for an already-exited child without killing anything.
    fn close(&self) {
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

fn spawn_grouped(cmd: &mut Command) -> R<Grouped> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    #[cfg(windows)]
    let job = assign_job(&child)?;
    Ok(Grouped {
        child,
        #[cfg(windows)]
        job,
    })
}

// -------------------------------- subprocess --------------------------------

fn cargo(root: &Path, env: Option<(&str, &str)>, args: &[&str]) -> R {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root).args(args);
    if let Some((k, v)) = env {
        cmd.env(k, v);
    }
    run(&mut cmd)
}

/// Run a command to completion, failing on a non-zero exit.
pub fn run(cmd: &mut Command) -> R {
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("running {cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        fail(format!("{cmd:?} exited with {status}"))
    }
}

/// Best-effort teardown of any process still running the binary at `path`. The
/// application dies with its guardian on Linux (`PR_SET_PDEATHSIG`) and Windows (the
/// kill-on-close Job Object), so this only matters on macOS, where a guardian teardown
/// can orphan the app's own process group; `pkill -f` reaps it. Harmless elsewhere.
pub fn kill_stray(path: &Path) {
    #[cfg(unix)]
    {
        let install = path.parent().map(|parent| parent.join("install"));
        for pattern in std::iter::once(path).chain(install.as_deref()) {
            let _ = Command::new("pkill")
                .arg("-9")
                .arg("-f")
                .arg(pattern)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    #[cfg(windows)]
    let _ = path; // the guardian's Job Object already tore the app down.
}

/// Extract the PID printed as `(pid N)` in the first log line containing `needle` — used
/// to target a specific child (e.g. the supervisor) inside the guardian's process tree.
pub fn pid_after(log: &str, needle: &str) -> Option<u32> {
    let at = log.find(needle)?;
    let rest = &log[at..];
    let open = rest.find("(pid ")? + "(pid ".len();
    let close = rest[open..].find(')')?;
    rest[open..open + close].trim().parse().ok()
}

/// Extract the decimal PID immediately following `needle`, as printed by the
/// supervisor after the guardian returns the OS-derived child PID.
pub fn pid_number_after(log: &str, needle: &str) -> Option<u32> {
    let at = log.find(needle)? + needle.len();
    let digits: String = log[at..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

/// Kill one process by PID (not its group/tree) — to simulate a supervisor crash while
/// the guardian and the application keep running.
pub fn kill_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .arg("/F")
        .arg("/PID")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Ask a process to stop *gracefully* (Unix `SIGTERM`; Windows `CTRL_BREAK_EVENT`) —
/// what an init system sends on a clean stop, so a test can prove the guardian forwards it.
pub fn term_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
        // `Proc::spawn` makes the child a process-group leader, whose group id is its PID.
        // Targeting that group exercises the guardian's console shutdown handler without
        // terminating it externally or signalling unrelated E2E processes.
        let _ = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
    }
}

/// Whether a process with `pid` still exists — `kill(pid, 0)` on Unix (a running or unreaped
/// process answers; a fully-gone one gives `ESRCH`). Used to assert a tree was reaped.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as libc::pid_t, 0) == 0
    }
    #[cfg(windows)]
    {
        // A best-effort check: `tasklist` lists the PID only while it exists.
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        out.map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

/// Kill any process still running from a previous run's work directory. On Unix an
/// interrupted run leaves the durable app processes behind (they outlive their
/// supervisor by design); on Windows the per-run job objects already tear them down.
pub fn reap_workdir(work: &Path) {
    #[cfg(unix)]
    let _ = Command::new("pkill")
        .arg("-9")
        .arg("-f")
        .arg(work)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    #[cfg(windows)]
    let _ = work;
}

/// Map an I/O error to the crate's `String` error type. Shared by the harness and
/// the scenarios (which reach it through the crate-root glob), so there is one such
/// converter, not one per module.
pub fn str_err(e: std::io::Error) -> String {
    e.to_string()
}
