//! Signed lifecycle-provider fixture for the operator demo.
//!
//! It intentionally models an over-engineered Java-era deployment, but implements
//! that process as one typed, idempotent state machine rather than a pile of shell
//! entrypoints. The agent downloads this executable as a provider artifact.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// The provider execution timeout the demo signs into its provider set, owned by this crate's
/// library so the fixture's budget and the value the demo publishes are one constant.
use demo_lifecycle::PROVIDER_TIMEOUT_MS;
use foundation::durable;
/// The reconciler protocol vocabulary is defined once, in the contracts crate; this fixture
/// answers exactly the operations the agent invokes.
use updated_contracts::reconciler::{attempt, Operation};

type Error = Box<dyn std::error::Error>;

/// Wall time an update `apply` spends outside its two dwells: one second each in `preflight`,
/// `prepare`, `drain` and `start`, two seconds for the filesystem work of the remaining steps,
/// and the budget `start` spends stopping the running workload and proving the candidate's own
/// entrypoint serves ([`WORKLOAD_START_BUDGET_MS`]).
const APPLY_FIXED_WORK_MS: u64 = 6_000 + WORKLOAD_START_BUDGET_MS;

/// How long `start` waits for the candidate's workload to answer on [`WORKLOAD_ADDRESS`] before
/// failing the activation. A release whose entrypoint cannot serve fails its own apply here,
/// rather than leaving the agent to infer it from a health observation.
const WORKLOAD_START_BUDGET_MS: u64 = 5_000;

/// The address this product's workload serves the fleet on — what the pod, its peers, and this
/// reconciler's own health observation all reach it at.
const WORKLOAD_ADDRESS: &str = "0.0.0.0:8080";

/// Headroom the dwell band leaves the timeout for everything wall time this fixture does not
/// control: process spawn, artifact staging, and a demo cluster under load.
const APPLY_MARGIN_MS: u64 = 3_000;

/// Shortest representative pause for a dwelling phase.
const DWELL_FLOOR_MS: u64 = 1_000;

/// The live files an update replaces, and therefore exactly what `prepare` copies aside and
/// `rollback` restores.
const ROLLBACK_SET: [&str; 3] = ["application.war", "content.repository", "server.xml"];

/// Longest one dwell may be: an `apply` performs two of them, and what is left of the provider
/// timeout after the fixed work and the margin has to cover both.
const DWELL_CEILING_MS: u64 = (PROVIDER_TIMEOUT_MS - APPLY_FIXED_WORK_MS - APPLY_MARGIN_MS) / 2;

struct Deployment {
    phase: Operation,
    attempt: String,
    candidate: String,
    predecessor: String,
    candidate_dir: PathBuf,
    reason: String,
    state: PathBuf,
    effects: PathBuf,
    live: PathBuf,
    backup: PathBuf,
}

impl Deployment {
    fn load() -> Result<Self, Error> {
        let mut args = std::env::args().skip(1);
        let phase = args
            .next()
            .ok_or("missing reconciler operation")?
            .parse::<Operation>()?;
        let values = named_arguments(args)?;
        let attempt = required_argument(&values, "--attempt-id")?.to_string();
        let candidate = required_argument(&values, "--candidate-version")?.to_string();
        let state = PathBuf::from(required_argument(&values, "--state-dir")?);
        Ok(Self {
            phase,
            effects: state.join("attempts").join(&attempt),
            live: state.join("legacy-java-home"),
            backup: state.join("backups").join(&attempt),
            state,
            attempt,
            candidate,
            predecessor: required_argument(&values, "--predecessor-version")?.to_string(),
            candidate_dir: PathBuf::from(required_argument(&values, "--candidate")?),
            reason: required_argument(&values, "--reason")?.to_string(),
        })
    }

    fn run(&self) -> Result<(), Error> {
        fs::create_dir_all(&self.effects)?;
        fs::create_dir_all(&self.live)?;
        fs::create_dir_all(self.state.join("audit"))?;
        // Completion markers make ONE update attempt idempotent, so a crash mid-apply resumes
        // without repeating finished work. A per-boot hook is not an attempt: the agent
        // invokes it under a constant id on every launch, so honouring a marker there would turn
        // "run this before every start" into "run this once, ever".
        if !matches!(self.phase, Operation::Healthcheck | Operation::Inspect)
            && !self.is_per_boot()
            && self.completed(self.phase)
        {
            return Ok(());
        }
        self.audit("started")?;
        match self.phase {
            Operation::Apply => self.apply()?,
            Operation::Healthcheck => self.periodic()?,
            Operation::Rollback => self.rollback()?,
            Operation::Inspect => self.fingerprint()?,
        }
        if !matches!(self.phase, Operation::Healthcheck | Operation::Inspect) && !self.is_per_boot()
        {
            self.write(
                self.effects.join(format!("{}.done", self.phase.as_str())),
                b"done\n",
            )?;
        }
        self.audit("completed")
    }

    fn apply(&self) -> Result<(), Error> {
        if self.reason == "restart" || self.candidate == self.predecessor {
            self.pre_start()?;
            return self.start();
        }
        self.preflight()?;
        self.write(self.effects.join("preflight.done"), b"done\n")?;
        self.prepare()?;
        self.write(self.effects.join("prepare.done"), b"done\n")?;
        self.pre_drain()?;
        self.write(self.effects.join("pre-drain.done"), b"done\n")?;
        self.drain()?;
        self.write(self.effects.join("drain.done"), b"done\n")?;
        self.stop()?;
        self.write(self.effects.join("stop.done"), b"done\n")?;
        self.pre_start()?;
        self.activate()?;
        self.write(self.effects.join("activate.done"), b"done\n")?;
        self.start()?;
        self.write(self.effects.join("start.done"), b"done\n")?;
        self.verify()?;
        self.write(self.effects.join("verify.done"), b"done\n")?;
        self.finalize()
    }

    fn preflight(&self) -> Result<(), Error> {
        executable(&self.candidate_dir.join("bin/app"))?;
        required_file(&self.candidate_dir.join("config/release.toml"))?;
        if self.candidate == self.predecessor {
            return Err("candidate and predecessor versions are identical".into());
        }
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    fn prepare(&self) -> Result<(), Error> {
        self.require("preflight")?;
        self.initialize_legacy_file("application.war", &self.predecessor)?;
        self.initialize_legacy_file("content.repository", "schema=1 owner=legacy")?;
        self.initialize_legacy_file(
            "server.xml",
            r#"<Server port="8005"><Service name="Catalina"/></Server>"#,
        )?;
        self.capture_rollback_backup()?;
        self.write(
            self.effects.join("generated-install.properties"),
            format!("candidate={} attempt={}\n", self.candidate, self.attempt).as_bytes(),
        )?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    /// Copy the predecessor's live state aside, exactly once per attempt.
    ///
    /// `apply` is replayed under the same attempt id — after a crash mid-apply, and by the
    /// agent's recovery activation, which re-invokes the hook with candidate and predecessor
    /// swapped. By then `activate` may already have written the candidate into `live`, so a second
    /// copy would overwrite the predecessor bytes that this attempt's `rollback` restores. The
    /// marker is written last, so a copy interrupted halfway is retaken rather than trusted.
    fn capture_rollback_backup(&self) -> Result<(), Error> {
        let marker = self.backup.join("captured");
        if marker.is_file() {
            return Ok(());
        }
        fs::create_dir_all(&self.backup)?;
        for name in ROLLBACK_SET {
            self.copy(&self.live.join(name), &self.backup.join(name))?;
        }
        self.write(marker, b"captured\n")
    }

    fn pre_drain(&self) -> Result<(), Error> {
        self.require("prepare")?;
        // Runs BEFORE the launcher withdraws readiness, while the app is still serving.
        // A real integration signals workers to stop accepting new sessions and lets
        // in-flight work wind down — meaningful wall-clock time in an enterprise app.
        self.write(
            self.live.join("pre-drain-signalled"),
            self.attempt.as_bytes(),
        )?;
        thread::sleep(self.dwell("pre-drain"));
        Ok(())
    }

    fn pre_start(&self) -> Result<(), Error> {
        // Runs BEFORE the process launches, on *every* launch — first install, plain
        // restart, and update — so unlike the update-only phases it requires no prior
        // step (there is no `stop` on a cold boot). `--reason` says which.
        // Per-boot environment prep lives here: seed a JBoss home, warm a mount, run
        // schema pre-checks. Minutes in real life; a representative pause here.
        fs::create_dir_all(&self.live)?;
        self.write(
            self.live.join("pre-start-prepared"),
            self.candidate.as_bytes(),
        )?;
        thread::sleep(self.dwell("pre-start"));
        Ok(())
    }

    /// A representative amount of operator work for one dwelling step, in the
    /// [`DWELL_FLOOR_MS`]–[`DWELL_CEILING_MS`] band. It is derived from the attempt id, the
    /// operation and the step, so it is stable across a step's crash-recovery retries (the work
    /// "takes as long as it takes") yet varies across agents and across the two dwelling steps of
    /// one `apply` — the fleet looks alive. The band is sized so that both dwells plus every fixed
    /// step still fit the provider's execution timeout with margin, for *every* attempt id.
    fn dwell(&self, step: &str) -> Duration {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in self
            .attempt
            .bytes()
            .chain(self.phase.as_str().bytes())
            .chain(step.bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Duration::from_millis(DWELL_FLOOR_MS + hash % (DWELL_CEILING_MS - DWELL_FLOOR_MS + 1))
    }

    fn drain(&self) -> Result<(), Error> {
        self.require("prepare")?;
        self.write(
            self.live.join("removed-from-load-balancer"),
            self.attempt.as_bytes(),
        )?;
        self.write(self.live.join("inflight-requests"), b"0\n")?;
        thread::sleep(Duration::from_secs(1));
        expect(&self.live.join("inflight-requests"), "0")
    }

    fn stop(&self) -> Result<(), Error> {
        self.require("drain")?;
        expect(&self.live.join("removed-from-load-balancer"), &self.attempt)?;
        // The drained workload is this hook's to stop; `start` brings the candidate's own
        // entrypoint up in its place.
        self.stop_workload()
    }

    fn activate(&self) -> Result<(), Error> {
        self.require("stop")?;
        self.write(self.live.join("application.war"), self.candidate.as_bytes())?;
        self.write(
            self.live.join("migration.plan"),
            format!("pending schema=2 version={}\n", self.candidate).as_bytes(),
        )?;
        self.copy(
            &self.effects.join("generated-install.properties"),
            &self.live.join("install.properties"),
        )?;
        Ok(())
    }

    /// Materialize the release's durable state, then converge the process onto it. This hook owns
    /// the workload — the agent starts none — so starting it is what `start` means. Convergence,
    /// not restart: a workload already running these bytes is left alone, so its pid is stable
    /// across agent boots, restarts and self-updates.
    fn start(&self) -> Result<(), Error> {
        self.publish_release()?;
        self.converge_workload()
    }

    /// The durable half of `start`: everything the release must have on disk before its process
    /// may run.
    fn publish_release(&self) -> Result<(), Error> {
        if self.attempt == attempt::BOOT {
            // Cold install and ordinary restart have no update transaction. Materialize any
            // provider-owned steady state that an update's activate/finalize phases would have
            // produced, without overwriting an existing deployment on restart.
            self.initialize_legacy_file("application.war", &self.candidate)?;
            self.initialize_legacy_file(
                "content.repository",
                &format!("schema=2 version={} migrated=true", self.candidate),
            )?;
            self.initialize_legacy_file(
                "change-ticket.receipt",
                &format!("green release {} established on boot", self.candidate),
            )?;
        } else {
            self.require("activate")?;
        }
        expect(&self.live.join("application.war"), &self.candidate)?;
        self.write(
            self.live.join("cache-warmup"),
            format!("warming caches for {}\n", self.candidate).as_bytes(),
        )?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    /// Prove the activation from durable live state.
    ///
    /// This hook, not the agent, owns the workload lifecycle, so the activation is proved from the
    /// durable live files it wrote rather than from a process it may not have started yet. The
    /// running application is evidence `periodic` collects, once there is a process to collect it
    /// from.
    fn verify(&self) -> Result<(), Error> {
        self.require("start")?;
        expect(&self.live.join("application.war"), &self.candidate)?;
        expect(
            &self.live.join("install.properties"),
            &format!("candidate={} attempt={}", self.candidate, self.attempt),
        )?;
        required_file(&self.live.join("migration.plan"))
    }

    /// Observe the running application, which only exists outside the activation transaction:
    /// `periodic` runs after the agent has relaunched the process (and after agent or
    /// pod restarts), so its evidence comes from durable live state and the live socket.
    fn verify_running_version(&self) -> Result<(), Error> {
        let observed = ureq::get("http://127.0.0.1:8080/version")
            .timeout(Duration::from_secs(2))
            .call()?
            .into_string()?;
        self.validate_running_version(&observed)
    }

    fn validate_running_version(&self, observed: &str) -> Result<(), Error> {
        if observed.trim() != self.candidate {
            return Err(format!("expected {}, observed {observed:?}", self.candidate).into());
        }
        Ok(())
    }

    fn periodic(&self) -> Result<(), Error> {
        // Perform one observation. Cadence, retry, timeout, and failure policy belong to the
        // hardened agent; the provider defines the application-specific evidence. Periodic is
        // deliberately independent of rollout-attempt markers: those belong to a completed
        // transaction and are not steady-state health.
        self.verify_running_version()?;
        // Finalization consumes the transient migration plan. Steady health proves the durable
        // post-finalize state instead of requiring transaction-temporary evidence.
        expect(
            &self.live.join("content.repository"),
            &format!("schema=2 version={} migrated=true", self.candidate),
        )?;
        required_file(&self.live.join("change-ticket.receipt"))
    }

    fn fingerprint(&self) -> Result<(), Error> {
        // The provider chooses the measured state; the agent hashes these exact bytes and
        // never logs them. Keep the representation explicit and stable across filesystem order.
        self.periodic()?;
        let application = fs::read_to_string(self.live.join("application.war"))?;
        let repository = fs::read_to_string(self.live.join("content.repository"))?;
        let server = fs::read_to_string(self.live.join("server.xml"))?;
        print!(
            "application.war={application:?}\ncontent.repository={repository:?}\nserver.xml={server:?}\n"
        );
        Ok(())
    }

    fn finalize(&self) -> Result<(), Error> {
        self.require("verify")?;
        self.write(
            self.live.join("content.repository"),
            format!("schema=2 version={} migrated=true\n", self.candidate).as_bytes(),
        )?;
        remove_if_present(&self.live.join("migration.plan"))?;
        remove_if_present(&self.live.join("removed-from-load-balancer"))?;
        self.write(
            self.live.join("change-ticket.receipt"),
            format!(
                "green release {} published by attempt {}\n",
                self.candidate, self.attempt
            )
            .as_bytes(),
        )
    }

    /// Restore the predecessor's durable state, then converge the process back onto it. On a
    /// rollback `--candidate` IS the release being restored, so both directions converge the
    /// workload the same way onto the same argument.
    fn rollback(&self) -> Result<(), Error> {
        self.restore_release()?;
        self.converge_workload()
    }

    /// The durable half of `rollback`.
    fn restore_release(&self) -> Result<(), Error> {
        for name in ROLLBACK_SET {
            let source = self.backup.join(name);
            if source.is_file() {
                self.copy(&source, &self.live.join(name))?;
            }
        }
        remove_if_present(&self.live.join("migration.plan"))?;
        remove_if_present(&self.live.join("removed-from-load-balancer"))?;
        Ok(())
    }

    fn require(&self, phase: &str) -> Result<(), Error> {
        if self.effects.join(format!("{phase}.done")).is_file() {
            Ok(())
        } else {
            Err(format!("{} requires completed {phase}", self.phase.as_str()).into())
        }
    }

    /// Whether this invocation is the agent's per-boot environment hook (`install`/`restart`
    /// reasons, run on every launch under a constant attempt id) rather than one update attempt.
    fn is_per_boot(&self) -> bool {
        matches!(self.reason.as_str(), "install" | "restart")
    }

    fn completed(&self, phase: Operation) -> bool {
        self.effects
            .join(format!("{}.done", phase.as_str()))
            .is_file()
    }

    fn initialize_legacy_file(&self, name: &str, value: &str) -> Result<(), Error> {
        let path = self.live.join(name);
        if !path.exists() {
            self.write(path, value.as_bytes())?;
        }
        Ok(())
    }

    fn write(&self, path: PathBuf, bytes: &[u8]) -> Result<(), Error> {
        durable::atomic_write(&path, ".demo-lifecycle", bytes)?;
        Ok(())
    }

    fn copy(&self, source: &Path, destination: &Path) -> Result<(), Error> {
        self.write(destination.to_path_buf(), &fs::read(source)?)
    }

    fn audit(&self, event: &str) -> Result<(), Error> {
        let mut log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.state.join("audit/lifecycle.tsv"))?;
        writeln!(log, "{}\t{}\t{event}", self.phase.as_str(), self.attempt)?;
        log.sync_all()?;
        Ok(())
    }
}

/// Workload ownership: starting, stopping, and observing the release's own entrypoint.
///
/// The agent runs packages and never starts, stops, or holds a pid of a workload, so the release's
/// reconciler is the only thing that can. The record of what is running is deliberately *not*
/// per-provider: a node's next release may ship a different reconciler, and that reconciler has to
/// be able to stop the process its predecessor started. It therefore lives beside the per-provider
/// state directories, at the same path the base fleet's reconciler derives from its own
/// `--state-dir` (`crates/updatec/e2e/release-server.sh`).
impl Deployment {
    fn workload_record(&self, name: &str) -> PathBuf {
        self.state
            .parent()
            .unwrap_or(self.state.as_path())
            .join(name)
    }

    fn workload_pid(&self) -> Option<i32> {
        fs::read_to_string(self.workload_record("workload.pid"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Whether the recorded workload is still serving. A detached workload is reparented to
    /// whatever runs as pid 1, which reaps its own children and nothing else, so a crashed one
    /// lingers as a zombie that answers `kill -0` and serves nothing: the process state, not its
    /// mere existence, is what says the workload is still there.
    fn workload_running(&self) -> bool {
        let Some(pid) = self.workload_pid() else {
            return false;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        // The comm field is parenthesized and may itself contain spaces; the process state is the
        // first field after the closing parenthesis.
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| !rest.starts_with('Z'))
    }

    /// Stop the running workload, whichever release's reconciler started it, and forget it.
    fn stop_workload(&self) -> Result<(), Error> {
        if let Some(pid) = self.workload_pid() {
            signal(pid, libc::SIGTERM);
            for _ in 0..5 {
                if !self.workload_running() {
                    break;
                }
                thread::sleep(Duration::from_secs(1));
            }
            if self.workload_running() {
                signal(pid, libc::SIGKILL);
                thread::sleep(Duration::from_millis(200));
            }
        }
        remove_if_present(&self.workload_record("workload.pid"))?;
        remove_if_present(&self.workload_record("workload.release"))
    }

    /// Converge the workload onto the candidate: leave one already running these bytes alone,
    /// otherwise stop what is running and start the candidate's own entrypoint, detached into its
    /// own session so it belongs to the release rather than to this bounded invocation (the agent
    /// tears the hook's process tree down the moment the hook returns).
    fn converge_workload(&self) -> Result<(), Error> {
        let release =
            fs::read_to_string(self.workload_record("workload.release")).unwrap_or_default();
        if self.workload_running() && release.trim() == self.candidate {
            return Ok(());
        }
        self.stop_workload()?;
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.workload_record("workload.log"))?;
        let pidfile = self.workload_record("workload.pid");
        let mut command = std::process::Command::new(self.candidate_dir.join("bin/app"));
        command
            .current_dir(&self.candidate_dir)
            .args(["--addr", WORKLOAD_ADDRESS, "--await-record"])
            .arg(&pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        detach(&mut command);
        let child = command.spawn()?;
        // The entrypoint refuses to serve until this record names it: a workload nothing can name
        // is a workload nothing can stop.
        self.write(pidfile, format!("{}\n", child.id()).as_bytes())?;
        self.await_workload()?;
        self.write(
            self.workload_record("workload.release"),
            format!("{}\n", self.candidate).as_bytes(),
        )
    }

    /// Wait for the started workload to serve its own version, within the budget `apply`'s dwell
    /// arithmetic reserves for it. A release whose entrypoint cannot run at all fails its own
    /// activation here.
    fn await_workload(&self) -> Result<(), Error> {
        let deadline = std::time::Instant::now() + Duration::from_millis(WORKLOAD_START_BUDGET_MS);
        let mut last = String::from("no response");
        while std::time::Instant::now() < deadline {
            match self.observed_version() {
                Ok(observed) if observed.trim() == self.candidate => return Ok(()),
                Ok(observed) => last = format!("serving {observed:?}"),
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(format!(
            "the workload from {} never served {} ({last})",
            self.candidate_dir.display(),
            self.candidate
        )
        .into())
    }

    fn observed_version(&self) -> Result<String, Error> {
        Ok(ureq::get("http://127.0.0.1:8080/version")
            .timeout(Duration::from_secs(2))
            .call()?
            .into_string()?)
    }
}

/// Move the workload into its own session, out of the hook invocation's contained tree.
#[cfg(unix)]
fn detach(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // Safety: `setsid` is async-signal-safe and touches no allocator or lock the forked child
    // could have inherited mid-update.
    unsafe {
        command.pre_exec(|| match libc::setsid() {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
}

#[cfg(unix)]
fn signal(pid: i32, signal: libc::c_int) {
    // Safety: `kill` on a pid that has exited fails with ESRCH; nothing here is unsound.
    unsafe {
        libc::kill(pid, signal);
    }
}

fn named_arguments(
    mut args: impl Iterator<Item = String>,
) -> Result<std::collections::BTreeMap<String, String>, Error> {
    let mut values = std::collections::BTreeMap::new();
    while let Some(name) = args.next() {
        if name == "--" {
            break;
        }
        if !name.starts_with("--") {
            return Err(format!("unexpected reconciler argument {name:?}").into());
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {name}"))?;
        values.insert(name, value);
    }
    if values.get("--protocol").map(String::as_str) != Some("1") {
        return Err("unsupported or missing reconciler protocol".into());
    }
    Ok(values)
}

fn required_argument<'a>(
    values: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, Error> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {name}").into())
}

fn required_file(path: &Path) -> Result<(), Error> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing required file {}", path.display()).into())
    }
}

fn executable(path: &Path) -> Result<(), Error> {
    required_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o111 == 0 {
            return Err(format!("{} is not executable", path.display()).into());
        }
    }
    Ok(())
}

fn expect(path: &Path, expected: &str) -> Result<(), Error> {
    let actual = fs::read_to_string(path)?;
    if actual.trim() == expected {
        Ok(())
    } else {
        Err(format!(
            "{} contains {actual:?}, expected {expected:?}",
            path.display()
        )
        .into())
    }
}

fn remove_if_present(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn main() {
    if let Err(error) = Deployment::load().and_then(|deployment| deployment.run()) {
        eprintln!("demo lifecycle failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hook may only read flags the agent actually emits. A flag deleted from the published
    /// grammar must fail here rather than silently become an always-absent value at runtime.
    #[test]
    fn every_flag_this_hook_reads_is_one_the_agent_emits() {
        const SOURCE: &str = include_str!("main.rs");
        let mut read = Vec::new();
        let mut rest = SOURCE;
        while let Some(at) = rest.find("required_argument(&values, \"") {
            rest = &rest[at + "required_argument(&values, \"".len()..];
            let end = rest.find('"').expect("a terminated flag literal");
            read.push(&rest[..end]);
            rest = &rest[end..];
        }
        assert!(!read.is_empty(), "the flag reads must be discoverable");
        for flag in read {
            assert!(
                updated_contracts::reconciler::FLAGS.contains(&flag),
                "{flag} is read by this hook but is not part of the published invocation grammar"
            );
        }
    }

    fn deployment(root: PathBuf, phase: Operation, attempt: &str) -> Deployment {
        Deployment {
            phase,
            attempt: attempt.into(),
            candidate: "22.0.0".into(),
            predecessor: "1.0.0".into(),
            candidate_dir: root.join("candidate"),
            reason: "update".into(),
            state: root.clone(),
            effects: root.join("attempts").join(attempt),
            live: root.join("live"),
            backup: root.join("backups").join(attempt),
        }
    }

    #[test]
    fn an_update_apply_fits_the_signed_provider_timeout_for_every_attempt_id() {
        // The agent bounds the whole hook invocation by the provider timeout the demo signs
        // in, so the WORST case over attempt ids — fixed work plus both dwells — has to fit it
        // with margin. Otherwise a healthy candidate is killed mid-apply and the cohort rolls
        // back, deterministically for that attempt id (the retry re-runs the same steps).
        let root = PathBuf::from("/nonexistent");
        let mut worst = Duration::ZERO;
        for id in 0..5_000u32 {
            let deployment = deployment(root.clone(), Operation::Apply, &format!("attempt-{id}"));
            let pre_drain = deployment.dwell("pre-drain");
            let pre_start = deployment.dwell("pre-start");
            for dwell in [pre_drain, pre_start] {
                assert!(
                    (Duration::from_millis(DWELL_FLOOR_MS)
                        ..=Duration::from_millis(DWELL_CEILING_MS))
                        .contains(&dwell),
                    "dwell {dwell:?} outside the band for attempt-{id}"
                );
            }
            worst = worst.max(pre_drain + pre_start);
        }
        let apply = Duration::from_millis(APPLY_FIXED_WORK_MS) + worst;
        assert!(
            apply + Duration::from_millis(APPLY_MARGIN_MS)
                <= Duration::from_millis(PROVIDER_TIMEOUT_MS),
            "worst-case apply {apply:?} leaves less than the margin under the provider timeout"
        );
    }

    #[test]
    fn the_two_dwells_of_one_apply_differ() {
        // Both dwells run under Operation::Apply in one process. Keying only on attempt+operation
        // made them identical, doubling the longest dwell into the timeout; the step must vary it.
        let root = PathBuf::from("/nonexistent");
        let mut distinct = 0;
        for id in 0..1_000u32 {
            let deployment = deployment(root.clone(), Operation::Apply, &format!("attempt-{id}"));
            if deployment.dwell("pre-drain") != deployment.dwell("pre-start") {
                distinct += 1;
            }
        }
        assert!(
            distinct > 900,
            "dwells barely vary across steps: {distinct}"
        );
    }

    #[test]
    fn a_dwell_is_stable_across_crash_recovery_retries_of_its_step() {
        let root = PathBuf::from("/nonexistent");
        let first = deployment(root.clone(), Operation::Apply, "attempt-7").dwell("pre-drain");
        let retry = deployment(root, Operation::Apply, "attempt-7").dwell("pre-drain");
        assert_eq!(first, retry);
    }

    #[test]
    fn cold_boot_start_does_not_require_an_update_activation() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let mut deployment = deployment(root.clone(), Operation::Apply, attempt::BOOT);
        deployment.reason = "install".into();
        fs::create_dir_all(&deployment.live).unwrap();

        assert!(!deployment.effects.join("activate.done").exists());
        deployment.publish_release().unwrap();
        expect(&deployment.live.join("application.war"), "22.0.0").unwrap();
        expect(
            &deployment.live.join("content.repository"),
            "schema=2 version=22.0.0 migrated=true",
        )
        .unwrap();
        required_file(&deployment.live.join("change-ticket.receipt")).unwrap();
    }

    #[test]
    fn in_transaction_verification_does_not_probe_the_stopped_application() {
        // The agent stops the managed process before it invokes the activation hook and only
        // relaunches it afterwards, so nothing is listening while `verify` runs. Verification must
        // come from durable live state, or every update fails and rolls back.
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let deployment = deployment(root.clone(), Operation::Apply, "T");
        fs::create_dir_all(&deployment.effects).unwrap();
        fs::create_dir_all(&deployment.live).unwrap();
        fs::write(deployment.effects.join("start.done"), b"done\n").unwrap();
        fs::write(deployment.live.join("application.war"), b"22.0.0\n").unwrap();
        fs::write(
            deployment.live.join("install.properties"),
            b"candidate=22.0.0 attempt=T\n",
        )
        .unwrap();
        fs::write(
            deployment.live.join("migration.plan"),
            b"pending schema=2 version=22.0.0\n",
        )
        .unwrap();

        deployment.verify().unwrap();
    }

    #[test]
    fn a_replayed_apply_keeps_the_attempts_original_rollback_backup() {
        // A crash after `activate` but before `apply.done` — or the agent's recovery
        // activation, which re-invokes `apply` under the same attempt id — replays `prepare` with
        // the candidate already in `live`. Re-copying then would leave `rollback` restoring the
        // candidate's bytes as if they were the predecessor's.
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let deployment = deployment(root.clone(), Operation::Apply, "T");
        fs::create_dir_all(&deployment.effects).unwrap();
        fs::create_dir_all(&deployment.live).unwrap();
        fs::write(deployment.effects.join("preflight.done"), b"done\n").unwrap();

        deployment.prepare().unwrap();
        expect(&deployment.backup.join("application.war"), "1.0.0").unwrap();

        fs::write(deployment.live.join("application.war"), b"22.0.0\n").unwrap();
        deployment.prepare().unwrap();
        expect(&deployment.backup.join("application.war"), "1.0.0").unwrap();

        deployment.restore_release().unwrap();
        expect(&deployment.live.join("application.war"), "1.0.0").unwrap();
    }

    #[test]
    fn steady_state_verification_does_not_require_transaction_markers() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let live = root.join("live");
        fs::create_dir_all(&live).unwrap();
        fs::write(
            live.join("content.repository"),
            b"schema=2 version=22.0.0 migrated=true\n",
        )
        .unwrap();
        fs::write(live.join("change-ticket.receipt"), b"complete\n").unwrap();
        let deployment = deployment(root.clone(), Operation::Healthcheck, "healthcheck");

        assert!(!deployment.effects.join("start.done").exists());
        assert!(!deployment.live.join("migration.plan").exists());
        deployment.validate_running_version("22.0.0\n").unwrap();
        expect(
            &deployment.live.join("content.repository"),
            "schema=2 version=22.0.0 migrated=true",
        )
        .unwrap();
        required_file(&deployment.live.join("change-ticket.receipt")).unwrap();
    }
}
