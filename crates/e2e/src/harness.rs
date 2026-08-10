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

/// Failure ceiling for positive E2E events. Pollers return immediately on success;
/// this only prevents a resource-starved CI runner from turning latency into a flake.
pub const EVENT_TIMEOUT: u64 = 600;

/// How long a NEGATIVE readiness expectation must hold. Unlike a positive event, "still not ready"
/// cannot be proven by one observation — it has to be watched for a while, long enough to cover the
/// health grace the scenario configured plus a launch.
pub const READINESS_SETTLE: u64 = 15;

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
pub struct LogReader {
    done: std::sync::mpsc::Receiver<()>,
    thread: std::thread::JoinHandle<()>,
}

impl LogReader {
    fn finish(self) {
        // Descendants can accidentally retain an inherited output handle. Never let that
        // turn diagnostic log draining into an unbounded E2E teardown hang.
        if self.done.recv_timeout(Duration::from_secs(1)).is_ok() {
            let _ = self.thread.join();
        }
    }
}

pub fn tee(
    label: &str,
    stream: Option<impl Read + Send + 'static>,
    buf: &LogBuf,
) -> Option<LogReader> {
    let stream = stream?;
    let (buf, label) = (buf.clone(), label.to_string());
    let (done_tx, done) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Err(error) => {
                    if let Ok(mut b) = buf.lock() {
                        b.push_str(&format!("log capture failed: {error}\n"));
                    }
                    break;
                }
                Ok(_) => {
                    // Avoid square-bracket prefixes: Windows CI log relays have been
                    // observed rendering their bytes as `Ä` and `Å`.
                    eprint!("{label}: {line}");
                    if let Ok(mut b) = buf.lock() {
                        b.push_str(&line);
                    }
                }
            }
        }
        let _ = done_tx.send(());
    });
    Some(LogReader { done, thread })
}

/// Shared paths and build outputs for one run.
pub struct Ctx {
    _run_lock: std::fs::File,
    pub root: PathBuf,
    pub work: PathBuf,
    /// Cargo's build-output dir for this driver. `e2e` uses the shared `target/`; a differently
    /// named driver (the kill fuzzer) gets its own `target/<name>-cargo` so its `cargo build`
    /// never unlinks a shared `target/release/*` artifact out from under a concurrent e2e run
    /// (which surfaced as the launcher's transient `inspecting supervisor: No such file`).
    pub target: PathBuf,
    pub server: PathBuf,
    pub supervisor: PathBuf,
    pub bootstrap: PathBuf,
    /// Rust's own OS-arch key, e.g. `macos-aarch64` / `windows-x86_64`; matches
    /// what the agent sends and the server keys manifests by.
    pub platkey: String,
    /// `.exe` on Windows, empty elsewhere.
    pub exe: &'static str,
    /// `E2E_FIPS` was set for this run: every binary that does crypto builds `--features fips`.
    pub fips: bool,
}

/// The cargo features every agent build in the run uses: `chaos` for the crash-injection
/// points the recovery scenarios need, plus `fips` under `E2E_FIPS` so the agents the
/// self-update scenarios publish and run link the validated provider too — the same binary
/// shape as `Ctx::supervisor`. One source of truth, so no agent fixture can silently
/// drop out of FIPS mode (and so feature unification never rebuilds the agent between
/// fixtures).
pub fn supervisor_features(fips: bool) -> &'static [&'static str] {
    if fips {
        &["chaos", "fips"]
    } else {
        &["chaos"]
    }
}

impl Ctx {
    /// The e2e scenario runner's harness. Uses the `e2e`-named lock + workdir.
    pub fn new() -> R<Ctx> {
        Self::named("e2e")
    }

    /// A harness with its own `target/<name>.lock` and `target/<name>-work` build/run directory, so
    /// independent drivers (the e2e suite vs. the standalone kill fuzzer) never share a lock or
    /// clobber each other's workdir and can run concurrently.
    pub fn named(name: &str) -> R<Ctx> {
        // crates/e2e/ -> workspace root.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("cannot locate workspace root")?
            .to_path_buf();
        let work = root.join(format!("target/{name}-work"));
        let lock_path = root.join(format!("target/{name}.lock"));
        // Every driver builds into its own `target/<name>-cargo`, so concurrent `cargo build`s
        // (and the dev tree's own `target/`) never unlink a shared `target/release/*` artifact out
        // from under each other — the collision that surfaced as the launcher's transient
        // `inspecting supervisor: No such file`. Point cargo (via `CARGO_TARGET_DIR`) and every
        // built-artifact path below at the same dir so builds and copies agree.
        let target = root.join(format!("target/{name}-cargo"));
        std::env::set_var("CARGO_TARGET_DIR", &target);
        let run_lock = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(str_err)?;
        let lock_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match run_lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < lock_deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return fail(format!(
                        "another run still owns {} after 10s; stop that run before retrying",
                        lock_path.display()
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return fail(format!(
                        "acquiring the shared ports/workdir lock {}: {error}",
                        lock_path.display()
                    ));
                }
            }
        }
        // An interrupted prior run can leave hook-managed workloads behind (they outlive the
        // node stack by design); reap them so they don't hold a port this run needs.
        reap_workdir(&work);
        match std::fs::remove_dir_all(&work) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return fail(format!("removing stale E2E workdir: {error}")),
        }
        std::fs::create_dir_all(work.join("build")).map_err(str_err)?;
        let exe = if cfg!(windows) { ".exe" } else { "" };
        let bin = |name: &str| target.join(format!("release/{name}{exe}"));
        Ok(Ctx {
            _run_lock: run_lock,
            server: bin("server"),
            // The canonical chaos-enabled supervisor is copied here by `build()`.
            // Versioned self-update fixture builds reuse Cargo's target path, so no
            // scenario may execute that mutable build output directly.
            supervisor: work.join(format!("build/supervisor-chaos{exe}")),
            bootstrap: bin("bootstrap"),
            platkey: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            exe,
            work,
            target,
            root,
            fips: std::env::var_os("E2E_FIPS").is_some(),
        })
    }

    /// Build the release binaries the harness drives. The agent is built with its
    /// `chaos` feature — the crash-injection points the chaos-recovery scenarios need,
    /// which are compiled out of every ordinary build.
    pub fn build(&self) -> R {
        // `E2E_FIPS=1` runs the suite on FIPS-validated crypto: the binaries that do crypto (the
        // mock CDN and agent — mTLS, the TUF transport, hashing,
        // signing) are built `--features fips`, which links the validated aws-lc-rs. The launcher
        // and sample apps do no crypto, so they build unchanged. A FIPS build that cannot validate
        // its provider fails closed at startup.
        let fips_feature: &[&str] = if self.fips {
            &["--features", "fips"]
        } else {
            &[]
        };
        let crypto_cdn = [
            ["build", "--release", "-p", "server"].as_slice(),
            fips_feature,
        ]
        .concat();
        cargo(&self.root, &crypto_cdn)?;
        cargo(&self.root, &["build", "--release", "-p", "bootstrap"])?;
        // Same package, env and features as every versioned agent fixture; only the
        // staged name differs.
        self.build_and_stage(
            "supervisor",
            &[],
            supervisor_features(self.fips),
            "supervisor-chaos",
        )?;
        Ok(())
    }

    /// Build one release package (with optional extra env and cargo `--features`) and stage the
    /// resulting binary at `build/<dst_stem><exe>`. The single build-then-copy path behind
    /// `build_app`, `build_supervisor`, and the post-ready-crash variant.
    fn build_and_stage(
        &self,
        pkg: &str,
        env: &[(&str, &str)],
        features: &[&str],
        dst_stem: &str,
    ) -> R<PathBuf> {
        let mut cmd = Command::new(env!("CARGO"));
        cmd.current_dir(&self.root);
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.args(["build", "--release", "-p", pkg]);
        if !features.is_empty() {
            cmd.arg("--features").arg(features.join(","));
        }
        run(&mut cmd)?;
        let src = self.target.join(format!("release/{pkg}{}", self.exe));
        let dst = self.work.join(format!("build/{dst_stem}{}", self.exe));
        std::fs::copy(&src, &dst).map_err(str_err)?;
        Ok(dst)
    }

    /// Build one version-agnostic sample binary. Release identity lives in its bundle config.
    pub fn build_app(&self, version: &str) -> R<PathBuf> {
        self.build_and_stage("sampleapp", &[], &[], &format!("app-{version}"))
    }

    /// Build `supervisor` with a baked version (so the bytes differ per version) and
    /// copy it to `build/supervisor-<v><exe>`, for the self-update scenarios.
    pub fn build_supervisor(&self, version: &str) -> R<PathBuf> {
        self.build_and_stage(
            "supervisor",
            &[("SUPERVISOR_VERSION", version)],
            supervisor_features(self.fips),
            &format!("supervisor-{version}"),
        )
    }

    /// Build a candidate that completes boot and signals ready, then exits
    /// before the launcher's confirmation window can commit it.
    pub fn build_post_ready_crashing_supervisor(&self, version: &str) -> R<PathBuf> {
        self.build_and_stage(
            "supervisor",
            &[
                ("SUPERVISOR_VERSION", version),
                ("SUPERVISOR_CHAOS_EXIT_AFTER_READY", "1"),
            ],
            supervisor_features(self.fips),
            &format!("supervisor-post-ready-crash-{version}"),
        )
    }

    /// The update-transaction boundaries the agent can crash at, enumerated from the
    /// binary itself (`--list-chaos-boundaries`, a chaos-feature build). One source of
    /// truth: the chaos scenario drives exactly the agent's crossings, so a boundary
    /// added or renamed on one side can never silently go untested on the other.
    pub fn chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-chaos-boundaries")
    }

    pub fn rollback_chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-rollback-chaos-boundaries")
    }

    pub fn install_chaos_boundaries(&self) -> R<Vec<String>> {
        self.list_chaos_boundaries("--list-install-chaos-boundaries")
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
            .arg(dir.join("keys")))?;
        // Mint the fleet mTLS material alongside the TUF keys, so the mock CDN can require client
        // certs and each agent can present one. Loopback SANs cover `https://127.0.0.1:port`.
        run(Command::new(&self.server)
            .arg("gen-certs")
            .arg("--dir")
            .arg(dir.join("certs"))
            .args(["--san", "127.0.0.1", "--san", "localhost"]))
    }

    /// Publish a per-platform release of `source` for `product` at `version`.
    pub fn publish(&self, dir: &Path, product: &str, version: &str, source: &Path) -> R {
        self.publish_with(dir, product, version, source, None)
    }

    /// Publish a release whose signed bundle archive is deliberately `kind`-corrupt (`garbage` /
    /// `truncate`) — a malformed-but-signed bundle for exercising the client's ingest rejection.
    pub fn publish_corrupt(
        &self,
        dir: &Path,
        product: &str,
        version: &str,
        source: &Path,
        kind: &str,
    ) -> R {
        self.publish_with(dir, product, version, source, Some(kind))
    }

    fn publish_with(
        &self,
        dir: &Path,
        product: &str,
        version: &str,
        source: &Path,
        corrupt: Option<&str>,
    ) -> R {
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
        if let Some(kind) = corrupt {
            command.args(["--corrupt", kind]);
        }
        run(&mut command)?;
        if application {
            let target = release_target(product, "stable", version, &self.platkey, product);
            let sha = self.target_sha256(dir, &target)?;
            std::fs::write(dir.join("desired-app"), format!("{target}\n{sha}\n"))
                .map_err(str_err)?;
            if let Ok(addr) = std::fs::read_to_string(dir.join("assignment-addr")) {
                self.publish_current_assignment(dir, addr.trim(), version)?;
            }
        }
        Ok(())
    }

    /// Serve the TUF repository at `dir/repo`; the returned handle keeps it alive.
    pub fn serve(&self, dir: &Path, addr: &str) -> R<Proc> {
        std::fs::write(dir.join("assignment-addr"), addr).map_err(str_err)?;
        let certs = dir.join("certs");
        let mut server = Proc::spawn(
            "server",
            Command::new(&self.server)
                .arg("serve")
                .arg("--repo")
                .arg(dir.join("repo"))
                .args(["--addr", addr])
                // Terminate mTLS: present the fleet server cert, require a client cert.
                .arg("--cert")
                .arg(certs.join("server.crt"))
                .arg("--key")
                .arg(certs.join("server.key"))
                .arg("--ca")
                .arg(certs.join("ca.crt")),
        )?;
        if !server.wait_for_log("serving ", EVENT_TIMEOUT) {
            let exited = server.has_exited();
            let output = server.captured_log();
            return fail(format!(
                "repository server did not become ready at {addr} (exited={exited}):\n{output}"
            ));
        }
        Ok(server)
    }

    fn publish_current_assignment(&self, dir: &Path, addr: &str, deployment: &str) -> R {
        // Only publish once the runtime fixture exists; the assignment builder itself is shared with
        // the `Sup` republish path in `fixtures`, so the format lives in one place.
        if !dir.join("assignment-runtime.json").exists() {
            return Ok(());
        }
        crate::fixtures::publish_assignment(
            &self.server,
            dir,
            &self.meta_url(addr),
            &self.targets_url(addr),
            deployment,
        )
    }

    /// The installer-pinned root a client trusts for the repo under `dir`.
    pub fn root(&self, dir: &Path) -> PathBuf {
        dir.join("repo/metadata/root.json")
    }

    pub fn target_sha256(&self, dir: &Path, name: &str) -> R<String> {
        // One implementation of the `server target-sha256` shell-out, in `fixtures`; this method
        // only supplies the server binary the `Ctx` already holds.
        crate::fixtures::target_sha256(&self.server, dir, name)
    }
    pub fn meta_url(&self, srv: &str) -> String {
        format!("https://{srv}/metadata/")
    }
    pub fn targets_url(&self, srv: &str) -> String {
        format!("https://{srv}/targets/")
    }
    /// A key file path under `dir/keys` (e.g. `root.pk8`). Only the Unix-only
    /// key-permissions scenario needs it.
    #[cfg(unix)]
    pub fn key(&self, dir: &Path, role: &str) -> PathBuf {
        dir.join(format!("keys/{role}.pk8"))
    }
}

pub fn release_target(
    product: &str,
    channel: &str,
    version: &str,
    platform: &str,
    component: &str,
) -> String {
    format!("products/{product}/{channel}/{version}/{platform}/{component}")
}

// ------------------------------- HTTP polling -------------------------------

/// Hex SHA-256 of a file — used to seed committed installed-target state. Delegates
/// to the same streaming hasher the node stack uses, so the harness and the production
/// path can never disagree on a digest. Fixture I/O failures are fatal rather than
/// becoming an empty digest that could make two missing files appear equal.
pub fn sha256_hex(path: &Path) -> R<String> {
    updated::hash::sha256_file(path)
        .map_err(|error| format!("hashing E2E fixture {}: {error}", path.display()))
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

/// Whether `cond` holds continuously for `secs`, polling throughout. Use this where a single
/// observation would be trivially satisfied by "the thing has not started yet" — a probe endpoint
/// that is not listening answers exactly like one answering "not ready".
pub fn stays_true(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if !cond() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    cond()
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
    grouped: Grouped,
    log: LogBuf,
    readers: Vec<LogReader>,
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
        // The tree teardown (process group on Unix, Job Object on Windows) is `spawn_grouped`'s
        // job.
        let mut grouped = spawn_grouped(cmd).map_err(|e| format!("spawn {label}: {e}"))?;
        let log = log_buf();
        let readers = [
            tee(label, grouped.child.stdout.take(), &log),
            tee(label, grouped.child.stderr.take(), &log),
        ]
        .into_iter()
        .flatten()
        .collect();
        Ok(Proc {
            grouped,
            log,
            readers,
        })
    }

    pub fn log_count(&self, needle: &str) -> usize {
        buf_count(&self.log, needle)
    }

    pub fn has_exited(&mut self) -> bool {
        matches!(self.grouped.child.try_wait(), Ok(Some(_)))
    }

    /// This process's own PID (the launcher's), so a test can signal it directly.
    pub fn pid(&self) -> u32 {
        self.grouped.child.id()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.grouped.teardown();
        let _ = self.grouped.child.wait();
        for reader in self.readers.drain(..) {
            reader.finish();
        }
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
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
            || AssignProcessToJobObject(job, child.as_raw_handle() as _) == 0
        {
            let error = std::io::Error::last_os_error();
            windows_sys::Win32::Foundation::CloseHandle(job);
            return fail(format!("configuring E2E process Job Object: {error}"));
        }
        Ok(job)
    }
}

// ------------------------------ init-system model ---------------------------

/// A process run under a *simulated init system*. Like systemd `Restart=on-failure`, it
/// relaunches the process whenever it exits, up to a start-limit burst, then gives up.
///
/// The launcher runs under the operator's init system, which owns its restarts; the harness has
/// no such service manager, so recovery paths (a rollback deferred to boot recovery, or reverting
/// an unconfirmed update) would never get a second boot to run in. `Service` is that init system. Output across every restart accumulates in one buffer, and `Drop` both stops
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
    /// (each revert costs a couple of boots); after it the node settles and no
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
        let readers = [
            tee(label, grouped.child.stdout.take(), log),
            tee(label, grouped.child.stderr.take(), log),
        ];
        loop {
            if stop.load(Ordering::SeqCst) {
                grouped.teardown();
                let _ = grouped.child.wait();
                for reader in readers.into_iter().flatten() {
                    reader.finish();
                }
                return;
            }
            match grouped.child.try_wait() {
                Ok(Some(_)) => break, // exited on its own → the init system restarts it
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        grouped.close();
        let _ = grouped.child.wait();
        for reader in readers.into_iter().flatten() {
            reader.finish();
        }
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
    /// Release the OS resources of an already-exited child, taking any surviving descendants with
    /// it — what a service manager does when the unit's main process exits (systemd's default
    /// `KillMode=control-group`, and a Windows job object closing).
    ///
    /// Windows got this for free (closing a kill-on-close job terminates what is left); Unix did
    /// not, so the same restart scenario left the managed application running on one platform and
    /// not the other, and the two were quietly testing different things.
    fn close(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
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

fn cargo(root: &Path, args: &[&str]) -> R {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root).args(args);
    run(&mut cmd)
}

/// Run a command to completion, failing on a non-zero exit.
pub fn run(cmd: &mut Command) -> R {
    // Capture both streams so a failing child (a cargo build, a server invocation)
    // reports *why* it failed, not just its exit code. On success we stay quiet.
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("running {cmd:?}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let mut detail = String::new();
    for (label, stream) in [("stderr", &output.stderr), ("stdout", &output.stdout)] {
        let text = String::from_utf8_lossy(stream);
        if !text.trim().is_empty() {
            detail.push_str(&format!("\n--- {label} ---\n{}", text.trim_end()));
        }
    }
    fail(format!("{cmd:?} exited with {}{detail}", output.status))
}

/// Durable-state diagnostics for a failed scenario: every `install/state` directory
/// under `work`, with the installed version, any recorded rejections, and whether an
/// update transaction is mid-flight. Printed automatically when a scenario fails, so a
/// failure never has to be diagnosed by guessing from streamed logs alone.
pub fn dump_install_state(work: &Path) -> String {
    let mut states = Vec::new();
    let mut stack = vec![work.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let is_state = path.file_name() == Some(std::ffi::OsStr::new("state"))
                && path.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("install"));
            if is_state {
                states.push(path);
            } else {
                stack.push(path);
            }
        }
    }
    states.sort();
    if states.is_empty() {
        return String::new();
    }
    let mut out = String::from("\n--- install-state diagnostics ---");
    for state in states {
        let label = state
            .strip_prefix(work)
            .unwrap_or(&state)
            .parent()
            .and_then(Path::parent)
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let installed_doc = std::fs::read_to_string(state.join("installed.json"))
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
        let installed = installed_doc
            .as_ref()
            .and_then(|doc| {
                doc.get("release")?
                    .get("version")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "none".into());
        // `confirmed=false` marks a provisional cold-install head still awaiting its first passing
        // health gate — the state that drives the ordered-fallback descent.
        let confirmed = installed_doc
            .as_ref()
            .and_then(|doc| doc.get("confirmed")?.as_bool())
            .map(|c| c.to_string())
            .unwrap_or_else(|| "n/a".into());
        let rejected = std::fs::read_to_string(state.join("rejected"))
            .map(|text| {
                let hashes: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
                if hashes.is_empty() {
                    "none".into()
                } else {
                    hashes.join(",")
                }
            })
            .unwrap_or_else(|_| "none".into());
        let transaction = if state.join("transaction.json").exists() {
            "IN-FLIGHT"
        } else {
            "none"
        };
        // Provider/pending presence: a rollback replays the *predecessor's own* providers held in
        // `pending`, so `lifecycle=none`/`pending=none` on a record that should have run rollback
        // hooks is the smoking gun for a rollback that skipped them (rather than product logic).
        let present = |key: &str| {
            installed_doc
                .as_ref()
                .map(|doc| {
                    if doc.get(key).is_some_and(|v| !v.is_null()) {
                        "yes"
                    } else {
                        "none"
                    }
                })
                .unwrap_or("n/a")
        };
        let (lifecycle, pending) = (present("lifecycle"), present("pending"));
        out.push_str(&format!(
            "\n  {label}: installed={installed} confirmed={confirmed} rejected=[{rejected}] \
             transaction={transaction} lifecycle={lifecycle} pending={pending}"
        ));
    }
    out
}

/// Extract the PID printed as `(pid N)` in the first log line containing `needle` — used to target
/// the agent process the launcher reports launching.
pub fn pid_after(log: &str, needle: &str) -> Option<u32> {
    let at = log.find(needle)?;
    let rest = &log[at..];
    let open = rest.find("(pid ")? + "(pid ".len();
    let close = rest[open..].find(')')?;
    rest[open..open + close].trim().parse().ok()
}

/// Kill one process by PID (not its group/tree) — to simulate an agent crash while the launcher
/// and the hook-managed workload keep running.
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

/// Kill any process still running from a previous run's work directory. A hook-managed workload
/// lives outside every tree the node stack owns — that is the whole model — so an interrupted run
/// leaves it behind; a scenario ends its own workload (`fixture::stop_workload`), and this reaps
/// what an interrupted run never got to.
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

/// Map any error to the crate's `String` error type. Shared by the harness and
/// the scenarios (which reach it through the crate-root glob), so there is one such
/// converter, not one per module.
pub fn str_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Make a fixture writable by the current operator without broadening permissions for
/// group/other users. Bundle installation intentionally removes write access, and several
/// corruption/repair scenarios need to model a deliberate local edit afterward.
pub fn make_owner_writable(path: &Path) -> R {
    let mut permissions = std::fs::metadata(path).map_err(str_err)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::PermissionsExt;
        const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
        permissions.set_attributes(permissions.attributes() & !FILE_ATTRIBUTE_READONLY);
    }
    std::fs::set_permissions(path, permissions).map_err(str_err)
}

#[cfg(test)]
mod tests {
    use super::supervisor_features;

    /// The self-update scenarios publish and run the fixtures `build_supervisor` /
    /// `build_post_ready_crashing_supervisor` produce, so those builds must carry `fips`
    /// under `E2E_FIPS` exactly as `Ctx::build`'s canonical supervisor does — otherwise a
    /// FIPS run exercises the TUF-fetch, digest-verify and staging path on default crypto.
    #[test]
    fn every_supervisor_build_is_chaos_and_gains_fips_with_the_run() {
        assert_eq!(supervisor_features(false), &["chaos"]);
        assert_eq!(supervisor_features(true), &["chaos", "fips"]);
    }
}
