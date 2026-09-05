//! Cross-platform test harness: workspace paths, `cargo` builds, the release
//! `server` CLI, HTTP polling, and a spawned process whose whole tree is torn
//! down on drop (process group on Unix, Job Object on Windows). Child output is
//! streamed to this process's stderr (so CI shows it inline) and captured in
//! memory for assertions — never written to log files.

use std::borrow::Cow;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    /// Cargo's isolated build-output dir for this driver.
    pub target: PathBuf,
    pub server: PathBuf,
    pub agent: PathBuf,
    /// Rust's own OS-arch key, e.g. `macos-aarch64` / `windows-x86_64`; matches
    /// what the agent sends and the server keys manifests by.
    pub platkey: String,
    /// `.exe` on Windows, empty elsewhere.
    pub exe: &'static str,
    /// `E2E_FIPS` was set for this run: every binary that does crypto builds `--features fips`.
    pub fips: bool,
}

/// The cargo features every agent build in the run uses: `chaos` for the crash-injection
/// points the recovery scenarios need, plus `fips` under `E2E_FIPS`.
pub fn agent_features(fips: bool) -> &'static [&'static str] {
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
        // from under each other — the collision that surfaced as the service's transient
        // `inspecting agent: No such file`. Point cargo (via `CARGO_TARGET_DIR`) and every
        // built-artifact path below at the same dir so builds and copies agree.
        let target = root.join(format!("target/{name}-cargo"));
        std::env::set_var("CARGO_TARGET_DIR", &target);
        let run_lock = foundation::file::open_lock_file(
            &lock_path,
            foundation::file::LockFileDisposition::OpenOrCreate,
        )
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
            // The canonical chaos-enabled agent is copied here by `build()`.
            agent: work.join(format!("build/agent-chaos{exe}")),
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
        // repository fixtures and agent — mTLS, the TUF transport, hashing,
        // signing) are built `--features fips`, which links the validated aws-lc-rs. Sample apps
        // do no crypto, so they build unchanged. A FIPS build that cannot validate
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
        // Same package, env and features as every versioned agent fixture; only the
        // staged name differs.
        self.build_and_stage(
            "agent",
            "updated-agent",
            &[],
            agent_features(self.fips),
            "agent-chaos",
        )?;
        Ok(())
    }

    /// Build one release package (with optional extra env and cargo `--features`) and stage the
    /// resulting binary at `build/<dst_stem><exe>`.
    fn build_and_stage(
        &self,
        pkg: &str,
        bin_stem: &str,
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
        run(cmd)?;
        let src = self.target.join(format!("release/{bin_stem}{}", self.exe));
        let dst = self.work.join(format!("build/{dst_stem}{}", self.exe));
        std::fs::copy(&src, &dst).map_err(str_err)?;
        Ok(dst)
    }

    /// Build one version-agnostic sample binary. Release identity lives in its bundle config.
    pub fn build_app(&self, version: &str) -> R<PathBuf> {
        self.build_and_stage(
            "sampleapp",
            "sampleapp",
            &[],
            &[],
            &format!("app-{version}"),
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
        let out = Command::new(&self.agent)
            .arg(flag)
            .output()
            .map_err(str_err)?;
        if !out.status.success() {
            return fail(format!("`agent {flag}` failed (chaos feature not built?)"));
        }
        let list: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if list.is_empty() {
            return fail("agent reported no chaos boundaries");
        }
        Ok(list)
    }

    /// Initialize independent routing and release TUF repositories. Routing is private and read
    /// through exact capabilities; release objects are fetched directly without a node identity.
    pub fn init_repo(&self, dir: &Path) -> R {
        for name in ["routing", "release"] {
            let mut command = Command::new(&self.server);
            command
                .arg("init")
                .arg("--repo")
                .arg(dir.join(format!("{name}-repo")))
                .arg("--keys")
                .arg(dir.join(format!("{name}-keys")));
            run(command)?;
        }
        // Mint the fleet TLS material alongside the TUF keys. The private capability fixture
        // validates agent certificates; the public object fixture only presents its server
        // certificate. Loopback SANs cover `https://127.0.0.1:port`.
        let mut command = Command::new(&self.server);
        command
            .arg("gen-certs")
            .arg("--dir")
            .arg(dir.join("certs"))
            .args(["--san", "127.0.0.1", "--san", "localhost"]);
        run(command)
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
        // The production publisher consumes a complete payload tree. The portable harness builds
        // one version-agnostic sample executable and gives each published release its identity in
        // config/release.toml, so materialize that tiny tree here instead of teaching the
        // production publisher a test-only "wrap this executable" input shape.
        let bundle: Cow<'_, Path> = if source.is_dir() {
            Cow::Borrowed(source)
        } else {
            let prepared = dir.join("publish-source");
            match std::fs::remove_dir_all(&prepared) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return fail(format!("removing stale payload source: {error}")),
            }
            std::fs::create_dir_all(prepared.join("bin")).map_err(str_err)?;
            std::fs::create_dir_all(prepared.join("config")).map_err(str_err)?;
            let entrypoint = prepared.join(format!("bin/app{}", self.exe));
            std::fs::copy(source, &entrypoint).map_err(str_err)?;
            // The former single-file publisher always installed its input as the payload
            // entrypoint. Preserve that contract for fixtures such as the executable shell
            // wedge, even though `File::create` gave their source a non-executable mode.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&entrypoint, std::fs::Permissions::from_mode(0o755))
                    .map_err(str_err)?;
            }
            std::fs::write(
                prepared.join("config/release.toml"),
                format!("version = \"{version}\"\n"),
            )
            .map_err(str_err)?;
            Cow::Owned(prepared)
        };
        crate::fixture::prepare_package(&bundle)?;
        let mut command = Command::new(&self.server);
        command
            .arg("publish-app")
            .arg("--repo")
            .arg(dir.join("release-repo"))
            .arg("--keys")
            .arg(dir.join("release-keys"))
            .args(["--product", product, "--version", version])
            .arg("--bundle")
            .arg(format!("{}={}", self.platkey, bundle.display()));
        if let Some(kind) = corrupt {
            command.args(["--corrupt", kind]);
        }
        run(command)?;
        let target = release_target(product, "stable", version, &self.platkey, product);
        let sha = self.target_sha256(dir, &target)?;
        std::fs::write(dir.join("desired-app"), format!("{target}\n{sha}\n")).map_err(str_err)?;
        if let Ok(addr) = std::fs::read_to_string(dir.join("assignment-addr")) {
            self.publish_current_assignment(dir, addr.trim(), version)?;
        }
        Ok(())
    }

    /// Serve the private routing repository through a capability gateway and the release
    /// repository through a distinct anonymous object origin. The returned handle owns both
    /// processes, preserving the existing one-lifetime-per-fixture contract.
    pub fn serve(&self, dir: &Path, addr: &str) -> R<Proc> {
        std::fs::write(dir.join("assignment-addr"), addr).map_err(str_err)?;
        let certs = dir.join("certs");
        let mut command = Command::new(&self.server);
        command
            .arg("serve-object")
            .arg("--repo")
            .arg(dir.join("release-repo"))
            .args(["--addr", "127.0.0.1:0"])
            .arg("--cert")
            .arg(certs.join("server.crt"))
            .arg("--key")
            .arg(certs.join("server.key"));
        let mut object = Proc::spawn("object-server", command)?;
        if !object.wait_for_log("serving object repository ", EVENT_TIMEOUT) {
            let exited = object.has_exited();
            let output = object.captured_log();
            return fail(format!(
                "object repository did not become ready (exited={exited}):\n{output}"
            ));
        }
        let object_log = object.captured_log();
        let object_url = object_log
            .lines()
            .find_map(|line| line.rsplit_once(" on ").map(|(_, url)| url.trim()))
            .filter(|url| url.starts_with("https://"))
            .ok_or("object repository did not report its bound HTTPS origin")?;
        let release_base_url = format!("{}/", object_url.trim_end_matches('/'));
        std::fs::write(dir.join("release-base-url"), &release_base_url).map_err(str_err)?;

        let mut command = Command::new(&self.server);
        command
            .arg("serve-capability")
            .arg("--repo")
            .arg(dir.join("routing-repo"))
            .args(["--addr", addr])
            .args(["--public-url", &format!("https://{addr}")])
            .arg("--cert")
            .arg(certs.join("server.crt"))
            .arg("--key")
            .arg(certs.join("server.key"))
            .arg("--ca")
            .arg(certs.join("ca.crt"));
        let mut gateway = Proc::spawn("capability-gateway", command)?;
        if !gateway.wait_for_log("serving capability repository ", EVENT_TIMEOUT) {
            let exited = gateway.has_exited();
            let output = gateway.captured_log();
            return fail(format!(
                "capability gateway did not become ready at {addr} (exited={exited}):\n{output}"
            ));
        }
        gateway.companions.push(object);
        Ok(gateway)
    }

    fn publish_current_assignment(&self, dir: &Path, _addr: &str, deployment: &str) -> R {
        // Only publish once the runtime fixture exists; the assignment builder itself is shared with
        // the `Sup` republish path in `fixtures`, so the format lives in one place.
        if !dir.join("assignment-runtime.json").exists() {
            return Ok(());
        }
        let release = self.release_base_url(dir)?;
        crate::fixtures::publish_assignment(
            &self.server,
            dir,
            &format!("{release}metadata/"),
            &format!("{release}targets/"),
            deployment,
        )
    }

    /// The installer-pinned root a client trusts for the repo under `dir`.
    pub fn root(&self, dir: &Path) -> PathBuf {
        dir.join("release-repo/metadata/root.json")
    }

    pub fn target_sha256(&self, dir: &Path, name: &str) -> R<String> {
        // One implementation of the `server target-sha256` shell-out, in `fixtures`; this method
        // only supplies the server binary the `Ctx` already holds.
        crate::fixtures::target_sha256(&self.server, dir, name)
    }
    fn release_base_url(&self, dir: &Path) -> R<String> {
        std::fs::read_to_string(dir.join("release-base-url")).map_err(str_err)
    }
    /// A key file path under `dir/keys` (e.g. `root.pk8`). Only the Unix-only
    /// key-permissions scenario needs it.
    #[cfg(unix)]
    pub fn key(&self, dir: &Path, role: &str) -> PathBuf {
        dir.join(format!("release-keys/{role}.pk8"))
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

/// How long a node may take to reach and commit its target state — a cold install, a descent past
/// heads it cannot run, a reconverge after a kill.
///
/// One constant, because it is one fact. It began as three function-local copies that had already
/// disagreed (120 in one scenario, 90 in two others), plus eight bare `120` literals in killfuzz
/// and one more in the application scenarios, with nothing saying why converging should be faster
/// in one place than another. A too-short bound here does not catch a bug, it invents a flake, so
/// the copies were not trading anything for the disagreement.
pub const CONVERGE_TIMEOUT: u64 = 120;

/// How long the node stack may take to disappear after it is killed — the service port released,
/// the version endpoint silent. Distinct from [`CONVERGE_TIMEOUT`] and much shorter: this bounds a
/// teardown that has already been commanded, not a convergence that has to do work.
pub const STOP_TIMEOUT: u64 = 20;

/// The canonical durable layout of the node rooted at `dir`.
///
/// [`updated::config::Paths::resolve`] is the single definition of that layout, and a scenario
/// asserting on `dir.join("install/state/installed.json")` is a second copy of it — one that keeps
/// passing after the real layout moves, because the file it looks for is simply never there and
/// "not settled" reads the same as "settled somewhere else". Every scenario derives its paths here
/// instead.
pub fn node_paths(dir: &std::path::Path) -> updated::config::Paths {
    updated::config::Paths::resolve(&dir.join("install"), &crate::fixtures::state_dir(dir))
}

/// Poll until the committed install record under `install_root` names `version`.
///
/// Serving a version and having *committed* it are different facts: a node can answer `/version`
/// from a running process whose install record never settled, and a restart then climbs back onto
/// the head it was supposed to have left. Every descent scenario asserts both, so the second half
/// is written once here rather than open-coded beside each first half.
pub fn wait_for_installed_version(dir: &std::path::Path, version: &str, secs: u64) -> bool {
    let state_path = node_paths(dir).installed;
    wait_until(secs, || {
        matches!(
            updated::state::read_installed(&state_path),
            updated::state::Installed::Present(ref state) if state.release.version == version
        )
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
    grouped: foundation::process::ContainedChild,
    log: LogBuf,
    readers: Vec<LogReader>,
    companions: Vec<Proc>,
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

    fn log_count(&self, needle: &str) -> usize {
        buf_count(self.log_buffer(), needle)
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
    pub fn spawn(label: &str, cmd: Command) -> R<Proc> {
        // The tree teardown (process group on Unix, Job Object on Windows) is `spawn_grouped`'s
        // job.
        let mut grouped = spawn_grouped(cmd).map_err(|e| format!("spawn {label}: {e}"))?;
        let log = log_buf();
        let readers = [
            tee(label, grouped.take_stdout(), &log),
            tee(label, grouped.take_stderr(), &log),
        ]
        .into_iter()
        .flatten()
        .collect();
        Ok(Proc {
            grouped,
            log,
            readers,
            companions: Vec::new(),
        })
    }

    pub fn has_exited(&mut self) -> bool {
        matches!(self.grouped.try_wait(), Ok(Some(_)))
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.grouped.stop(Duration::from_millis(400));
        for reader in self.readers.drain(..) {
            reader.finish();
        }
    }
}

// ------------------------------ init-system model ---------------------------

/// A process run under a *simulated init system*. Like systemd `Restart=on-failure`, it
/// relaunches the process whenever it exits, up to a start-limit burst, then gives up.
///
/// The agent runs under the operator's init system, which owns its restarts; the harness has
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
        let mut grouped = match spawn_grouped(cmd) {
            Ok(g) => g,
            Err(e) => {
                if let Ok(mut b) = log.lock() {
                    b.push_str(&format!("[{label}] service could not spawn: {e}\n"));
                }
                return;
            }
        };
        if let Ok(mut b) = log.lock() {
            b.push_str(&format!("service launched agent (pid {})\n", grouped.id()));
        }
        let readers = [
            tee(label, grouped.take_stdout(), log),
            tee(label, grouped.take_stderr(), log),
        ];
        loop {
            if stop.load(Ordering::SeqCst) {
                grouped.stop(Duration::from_millis(400));
                for reader in readers.into_iter().flatten() {
                    reader.finish();
                }
                return;
            }
            match grouped.try_wait() {
                Ok(Some(_)) => break, // exited on its own → the init system restarts it
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(error) => {
                    if let Ok(mut b) = log.lock() {
                        b.push_str(&format!("service wait failed: {error}\n"));
                    }
                    grouped.stop(Duration::ZERO);
                    break;
                }
            }
        }
        for reader in readers.into_iter().flatten() {
            reader.finish();
        }
        std::thread::sleep(Duration::from_millis(200)); // RestartSec
    }
}

/// Test processes use the production process-tree and parent-death containment primitive.
fn spawn_grouped(mut cmd: Command) -> R<foundation::process::ContainedChild> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    foundation::process::ContainedChild::spawn(cmd).map_err(|e| format!("spawn: {e}"))
}

// -------------------------------- subprocess --------------------------------

fn cargo(root: &Path, args: &[&str]) -> R {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(root).args(args);
    run(cmd)
}

/// Run a command to completion, failing on a non-zero exit.
pub fn run(cmd: Command) -> R {
    run_before(cmd, Instant::now() + Duration::from_secs(EVENT_TIMEOUT))
}

fn run_before(mut cmd: Command, deadline: Instant) -> R {
    use std::io::{Seek, SeekFrom};
    // A concurrent macOS spawn can inherit a pipe before std sets CLOEXEC. Completion
    // must depend on the child, never EOF from an unrelated process holding that pipe.
    let mut stdout = tempfile::tempfile().map_err(|e| e.to_string())?;
    let mut stderr = tempfile::tempfile().map_err(|e| e.to_string())?;
    cmd.stdout(stdout.try_clone().map_err(|e| e.to_string())?)
        .stderr(stderr.try_clone().map_err(|e| e.to_string())?);
    let description = format!("{cmd:?}");
    let status = foundation::process::run_to_exit(cmd, deadline);
    if matches!(status, Ok(Some(0))) {
        return Ok(());
    }
    let mut detail = String::new();
    for (label, stream) in [("stderr", &mut stderr), ("stdout", &mut stdout)] {
        stream.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        stream
            .take(1024 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&bytes);
        if !text.trim().is_empty() {
            detail.push_str(&format!("\n--- {label} ---\n{}", text.trim_end()));
        }
    }
    fail(format!("{description} finished with {status:?}{detail}"))
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
        // `maturity=provisional` marks a cold-install head still awaiting its first passing health
        // gate — the state that drives the cold-install-fallback descent.
        let maturity = installed_doc
            .as_ref()
            .and_then(|doc| doc.get("maturity")?.as_str())
            .map(str::to_owned)
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
        // Provider/guard presence: predecessor convergence uses the reconciler retained in
        // `rollback_guard`, so a missing binding on a guarded record is the smoking gun for a
        // rollback that cannot restore its predecessor.
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
        let (reconciler, rollback_guard) = (present("reconciler"), present("rollback_guard"));
        out.push_str(&format!(
            "\n  {label}: installed={installed} maturity={maturity} rejected=[{rejected}] \
             transaction={transaction} reconciler={reconciler} rollback-guard={rollback_guard}"
        ));
    }
    out
}

/// Extract the PID printed as `(pid N)` in the first log line containing `needle`.
pub fn pid_after(log: &str, needle: &str) -> Option<u32> {
    let at = log.find(needle)?;
    let rest = &log[at..];
    let open = rest.find("(pid ")? + "(pid ".len();
    let close = rest[open..].find(')')?;
    rest[open..open + close].trim().parse().ok()
}

/// Kill one process by PID (not its group/tree) to simulate an agent crash.
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
    {
        // `kill(pid, 0)` alone answers true for a ZOMBIE — a workload that crashed under an init
        // that has not reaped it — which is precisely the state a "did the workload survive?"
        // assertion must count as dead. `ps` reports state `Z` for a defunct process on both
        // Linux and macOS, so signal reachability is only the first half of the check.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } != 0 {
            return false;
        }
        Command::new("ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .map(|out| {
                let state = String::from_utf8_lossy(&out.stdout);
                out.status.success() && !state.trim_start().starts_with('Z')
            })
            .unwrap_or(false)
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
/// leaves it behind; a scenario ends its own workload through the `fixture::Workload` guard it
/// binds, and this reaps what an interrupted run never got to.
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path).map_err(str_err)?.permissions();
        permissions.set_mode(permissions.mode() | 0o200);
        std::fs::set_permissions(path, permissions).map_err(str_err)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
            INVALID_FILE_ATTRIBUTES,
        };

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is a live, NUL-terminated Windows path for both calls. Neither API keeps
        // the pointer. We preserve every attribute except READONLY instead of translating the
        // file through Unix permission semantics.
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if attributes & FILE_ATTRIBUTE_READONLY == 0 {
            return Ok(());
        }
        if unsafe { SetFileAttributesW(wide.as_ptr(), attributes & !FILE_ATTRIBUTE_READONLY) } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::agent_features;

    #[cfg(unix)]
    #[test]
    fn command_completion_does_not_wait_for_inherited_output() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & echo diagnostic >&2; exit 7"]);
        let start = std::time::Instant::now();
        let error = super::run(command).unwrap_err();
        assert!(error.contains("Some(7)"), "{error}");
        assert!(error.contains("diagnostic"), "{error}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn a_stuck_command_has_a_deadline() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let start = std::time::Instant::now();
        let error =
            super::run_before(command, start + std::time::Duration::from_millis(200)).unwrap_err();
        assert!(error.contains("TimedOut"), "{error}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    /// Every agent build carries chaos and gains FIPS with the run.
    #[test]
    fn every_agent_build_is_chaos_and_gains_fips_with_the_run() {
        assert_eq!(agent_features(false), &["chaos"]);
        assert_eq!(agent_features(true), &["chaos", "fips"]);
    }
}

#[cfg(all(test, unix))]
mod workload_guard_tests {
    use crate::fixture;

    /// The property, not the call sites: a scenario that returns early still ends its workload.
    /// The workload is deliberately outside every tree the node stack owns, so a missed teardown
    /// leaks a listener that holds the scenario's service address for the rest of the run — and
    /// nearly every teardown site sat after an early `return fail(...)`.
    #[test]
    fn an_early_return_still_reaps_the_workload() {
        let dir = std::env::temp_dir().join(format!("e2e-workload-guard-{}", std::process::id()));
        let root = fixture::root(&dir);
        std::fs::create_dir_all(&root).unwrap();
        // A grandchild, so it is reparented away from this process: a zombie of our own would read
        // as alive however it was signalled, and the workload the guard reaps is never this
        // process's child either.
        let spawned = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 60 >/dev/null 2>&1 & echo $!"])
            .output()
            .unwrap();
        let pid: u32 = String::from_utf8_lossy(&spawned.stdout)
            .trim()
            .parse()
            .unwrap();
        std::fs::write(
            root.join("workload.json"),
            format!("{{\"pid\":{pid},\"release\":\"r\",\"version\":\"1.0.0\"}}"),
        )
        .unwrap();

        fn scenario_that_fails_early(dir: &std::path::Path) -> Result<(), String> {
            let _workload = fixture::workload(dir);
            Err("the scenario failed before any teardown statement could run".into())
        }
        assert!(scenario_that_fails_early(&dir).is_err());
        assert!(
            !crate::harness::pid_alive(pid),
            "the guard must end the workload even on an early return"
        );
        assert!(fixture::workload_pid(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
