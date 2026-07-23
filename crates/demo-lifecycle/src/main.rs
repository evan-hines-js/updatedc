//! Signed lifecycle-provider fixture for the operator demo.
//!
//! It intentionally models an over-engineered Java-era deployment, but implements
//! that process as one typed, idempotent state machine rather than a pile of shell
//! entrypoints. The supervisor downloads this executable as a provider artifact.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use foundation::durable;

type Error = Box<dyn std::error::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Preflight,
    Prepare,
    PreDrain,
    Drain,
    Stop,
    PreStart,
    Activate,
    Start,
    Verify,
    Finalize,
    Rollback,
    Uninstall,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "preflight" => Ok(Self::Preflight),
            "prepare" => Ok(Self::Prepare),
            "pre-drain" => Ok(Self::PreDrain),
            "drain" => Ok(Self::Drain),
            "stop" => Ok(Self::Stop),
            "pre-start" => Ok(Self::PreStart),
            "activate" => Ok(Self::Activate),
            "start" => Ok(Self::Start),
            "verify" => Ok(Self::Verify),
            "finalize" => Ok(Self::Finalize),
            "rollback" => Ok(Self::Rollback),
            "uninstall" => Ok(Self::Uninstall),
            _ => Err(format!("unknown lifecycle phase {value:?}").into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Prepare => "prepare",
            Self::PreDrain => "pre-drain",
            Self::Drain => "drain",
            Self::Stop => "stop",
            Self::PreStart => "pre-start",
            Self::Activate => "activate",
            Self::Start => "start",
            Self::Verify => "verify",
            Self::Finalize => "finalize",
            Self::Rollback => "rollback",
            Self::Uninstall => "uninstall",
        }
    }
}

struct Deployment {
    phase: Phase,
    attempt: String,
    candidate: String,
    predecessor: String,
    candidate_dir: PathBuf,
    child_pid: Option<String>,
    state: PathBuf,
    effects: PathBuf,
    live: PathBuf,
    backup: PathBuf,
}

impl Deployment {
    fn load() -> Result<Self, Error> {
        let phase = Phase::parse(&required(updated::env::LIFECYCLE_PHASE)?)?;
        let attempt = required(updated::env::LIFECYCLE_ATTEMPT_ID)?;
        let candidate = required(updated::env::CANDIDATE_VERSION)?;
        let root = PathBuf::from(required(updated::env::INSTALL_ROOT)?);
        let state = root.join("demo-enterprise-deployment");
        Ok(Self {
            phase,
            effects: state.join("attempts").join(&attempt),
            live: state.join("legacy-java-home"),
            backup: state.join("backups").join(&attempt),
            state,
            attempt,
            candidate,
            predecessor: required(updated::env::PREDECESSOR_VERSION)?,
            candidate_dir: PathBuf::from(required(updated::env::CANDIDATE)?),
            child_pid: env::var(updated::env::CHILD_PID).ok(),
        })
    }

    fn run(&self) -> Result<(), Error> {
        fs::create_dir_all(&self.effects)?;
        fs::create_dir_all(&self.live)?;
        fs::create_dir_all(self.state.join("audit"))?;
        if self.completed(self.phase) {
            return Ok(());
        }
        self.audit("started")?;
        match self.phase {
            Phase::Preflight => self.preflight()?,
            Phase::Prepare => self.prepare()?,
            Phase::PreDrain => self.pre_drain()?,
            Phase::Drain => self.drain()?,
            Phase::Stop => self.stop()?,
            Phase::PreStart => self.pre_start()?,
            Phase::Activate => self.activate()?,
            Phase::Start => self.start()?,
            Phase::Verify => self.verify()?,
            Phase::Finalize => self.finalize()?,
            Phase::Rollback => self.rollback()?,
            Phase::Uninstall => self.uninstall()?,
        }
        self.write(
            self.effects.join(format!("{}.done", self.phase.name())),
            b"done\n",
        )?;
        self.audit("completed")
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
        self.require(Phase::Preflight)?;
        self.initialize_legacy_file("application.war", &self.predecessor)?;
        self.initialize_legacy_file("content.repository", "schema=1 owner=legacy")?;
        self.initialize_legacy_file(
            "server.xml",
            r#"<Server port="8005"><Service name="Catalina"/></Server>"#,
        )?;
        fs::create_dir_all(&self.backup)?;
        for name in ["application.war", "content.repository", "server.xml"] {
            self.copy(&self.live.join(name), &self.backup.join(name))?;
        }
        self.write(
            self.effects.join("generated-install.properties"),
            format!("candidate={} attempt={}\n", self.candidate, self.attempt).as_bytes(),
        )?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    fn pre_drain(&self) -> Result<(), Error> {
        self.require(Phase::Prepare)?;
        // Runs BEFORE the guardian withdraws readiness, while the app is still serving.
        // A real integration signals workers to stop accepting new sessions and lets
        // in-flight work wind down — meaningful wall-clock time in an enterprise app.
        self.write(
            self.live.join("pre-drain-signalled"),
            self.attempt.as_bytes(),
        )?;
        thread::sleep(self.dwell());
        Ok(())
    }

    fn pre_start(&self) -> Result<(), Error> {
        // Runs BEFORE the process launches, on *every* launch — first install, plain
        // restart, and update — so unlike the update-only phases it requires no prior
        // step (there is no `stop` on a cold boot). `UPDATED_LIFECYCLE_REASON` says which.
        // Per-boot environment prep lives here: seed a JBoss home, warm a mount, run
        // schema pre-checks. Minutes in real life; a representative pause here.
        fs::create_dir_all(&self.live)?;
        self.write(
            self.live.join("pre-start-prepared"),
            self.candidate.as_bytes(),
        )?;
        thread::sleep(self.dwell());
        Ok(())
    }

    /// A representative amount of operator work for this phase, in the 2–8s band. It is
    /// derived from the attempt id and phase, so it is stable across a phase's crash-recovery
    /// retries (the work "takes as long as it takes") yet varies across agents and phases —
    /// the fleet looks alive without any phase risking the provider's execution timeout.
    fn dwell(&self) -> Duration {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in self.attempt.bytes().chain(self.phase.name().bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Duration::from_millis(2000 + hash % 6001)
    }

    fn drain(&self) -> Result<(), Error> {
        self.require(Phase::Prepare)?;
        self.write(
            self.live.join("removed-from-load-balancer"),
            self.attempt.as_bytes(),
        )?;
        self.write(self.live.join("inflight-requests"), b"0\n")?;
        thread::sleep(Duration::from_secs(1));
        expect(&self.live.join("inflight-requests"), "0")
    }

    fn stop(&self) -> Result<(), Error> {
        self.require(Phase::Drain)?;
        expect(&self.live.join("removed-from-load-balancer"), &self.attempt)?;
        self.write(
            self.effects.join("stopped-process.pid"),
            self.child_pid.as_deref().unwrap_or("unknown").as_bytes(),
        )
    }

    fn activate(&self) -> Result<(), Error> {
        self.require(Phase::Stop)?;
        self.write(self.live.join("application.war"), self.candidate.as_bytes())?;
        self.write(
            self.live.join("migration.plan"),
            format!("pending schema=2 version={}\n", self.candidate).as_bytes(),
        )?;
        self.copy(
            &self.effects.join("generated-install.properties"),
            &self.live.join("install.properties"),
        )?;
        // Reload-in-place: the supervisor kept the app process running and passes its live PID
        // (`UPDATED_CHILD_PID`) only when this deployment reloads in place — i.e. this provider
        // ships an `activate` script. Signal it to reexec into the freshly activated release so
        // readiness proves the new version. In the guardian-restart variant (no `activate`
        // script) the supervisor stops the process before this phase and passes no PID, so this
        // is skipped and the guardian launches the new version instead.
        if let Some(pid) = self.child_pid.as_deref().filter(|pid| !pid.is_empty()) {
            let status = std::process::Command::new("kill")
                .args(["-HUP", pid])
                .status()?;
            if !status.success() {
                return Err(format!("signalling reload (kill -HUP {pid}) failed: {status}").into());
            }
        }
        Ok(())
    }

    fn start(&self) -> Result<(), Error> {
        self.require(Phase::Activate)?;
        expect(&self.live.join("application.war"), &self.candidate)?;
        self.write(
            self.live.join("cache-warmup"),
            format!("warming caches for {}\n", self.candidate).as_bytes(),
        )?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    }

    fn verify(&self) -> Result<(), Error> {
        self.require(Phase::Start)?;
        let observed = ureq::get("http://127.0.0.1:8080/version")
            .timeout(Duration::from_secs(2))
            .call()?
            .into_string()?;
        if observed.trim() != self.candidate {
            return Err(format!("expected {}, observed {observed:?}", self.candidate).into());
        }
        required_file(&self.live.join("migration.plan"))
    }

    fn finalize(&self) -> Result<(), Error> {
        self.require(Phase::Verify)?;
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

    fn rollback(&self) -> Result<(), Error> {
        for name in ["application.war", "content.repository", "server.xml"] {
            let source = self.backup.join(name);
            if source.is_file() {
                self.copy(&source, &self.live.join(name))?;
            }
        }
        remove_if_present(&self.live.join("migration.plan"))?;
        remove_if_present(&self.live.join("removed-from-load-balancer"))?;
        Ok(())
    }

    fn uninstall(&self) -> Result<(), Error> {
        // Decommission — the teardown mirror of prepare/activate/finalize. It removes the external
        // system of record this deployment established (the simulated legacy Java home: the WAR,
        // content repository, and generated configuration) — the state `updated` cannot see because
        // it lives outside the install root it owns. Idempotent: removing an already-removed tree is
        // success, so a replayed or partial wipe converges. It touches only what this provider
        // created; a real one must never delete a shared mount or database it merely used.
        remove_dir_all_if_present(&self.live)
    }

    fn require(&self, phase: Phase) -> Result<(), Error> {
        if self.completed(phase) {
            Ok(())
        } else {
            Err(format!("{} requires completed {}", self.phase.name(), phase.name()).into())
        }
    }

    fn completed(&self, phase: Phase) -> bool {
        self.effects
            .join(format!("{}.done", phase.name()))
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
        writeln!(log, "{}\t{}\t{event}", self.phase.name(), self.attempt)?;
        log.sync_all()?;
        Ok(())
    }
}

fn required(name: &str) -> Result<String, Error> {
    env::var(name).map_err(|_| format!("missing {name}").into())
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

fn remove_dir_all_if_present(path: &Path) -> Result<(), Error> {
    match fs::remove_dir_all(path) {
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
