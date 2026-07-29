//! Signed lifecycle-provider fixture for the operator demo.
//!
//! It intentionally models an over-engineered Java-era deployment, but implements
//! that process as one typed, idempotent state machine rather than a pile of shell
//! entrypoints. The supervisor downloads this executable as a provider artifact.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use foundation::durable;

type Error = Box<dyn std::error::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Apply,
    Healthcheck,
    Rollback,
    Inspect,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "apply" => Ok(Self::Apply),
            "healthcheck" => Ok(Self::Healthcheck),
            "rollback" => Ok(Self::Rollback),
            "inspect" => Ok(Self::Inspect),
            _ => Err(format!("unknown lifecycle phase {value:?}").into()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Healthcheck => "healthcheck",
            Self::Rollback => "rollback",
            Self::Inspect => "inspect",
        }
    }
}

struct Deployment {
    phase: Phase,
    attempt: String,
    candidate: String,
    predecessor: String,
    candidate_dir: PathBuf,
    managed_pid: Option<String>,
    reason: String,
    state: PathBuf,
    effects: PathBuf,
    live: PathBuf,
    backup: PathBuf,
}

impl Deployment {
    fn load() -> Result<Self, Error> {
        let mut args = std::env::args().skip(1);
        let phase = Phase::parse(&args.next().ok_or("missing reconciler operation")?)?;
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
            managed_pid: values.get("--managed-pid").cloned(),
            reason: required_argument(&values, "--reason")?.to_string(),
        })
    }

    fn run(&self) -> Result<(), Error> {
        fs::create_dir_all(&self.effects)?;
        fs::create_dir_all(&self.live)?;
        fs::create_dir_all(self.state.join("audit"))?;
        // Completion markers make ONE update attempt idempotent, so a crash mid-apply resumes
        // without repeating finished work. A per-boot hook is not an attempt: the supervisor
        // invokes it under a constant id on every launch, so honouring a marker there would turn
        // "run this before every start" into "run this once, ever".
        if !matches!(self.phase, Phase::Healthcheck | Phase::Inspect)
            && !self.is_per_boot()
            && self.completed(self.phase)
        {
            return Ok(());
        }
        self.audit("started")?;
        match self.phase {
            Phase::Apply => self.apply()?,
            Phase::Healthcheck => self.periodic()?,
            Phase::Rollback => self.rollback()?,
            Phase::Inspect => self.fingerprint()?,
        }
        if !matches!(self.phase, Phase::Healthcheck | Phase::Inspect) && !self.is_per_boot() {
            self.write(
                self.effects.join(format!("{}.done", self.phase.name())),
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
        self.require("prepare")?;
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
        // step (there is no `stop` on a cold boot). `--reason` says which.
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
        self.write(
            self.effects.join("stopped-process.pid"),
            self.managed_pid.as_deref().unwrap_or("unknown").as_bytes(),
        )
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

    fn start(&self) -> Result<(), Error> {
        if self.attempt == "boot" {
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

    fn verify(&self) -> Result<(), Error> {
        self.require("start")?;
        self.verify_running_version()?;
        required_file(&self.live.join("migration.plan"))
    }

    /// Observe the steady deployment without consulting transaction-local markers.
    ///
    /// `verify` runs inside the activation transaction and therefore proves that `start`
    /// completed in that same attempt. `periodic` runs after the transaction has finished
    /// (and after supervisor or pod restarts), so its evidence must come exclusively from
    /// durable live state and the running application.
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
        // The provider chooses the measured state; the supervisor hashes these exact bytes and
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

    fn require(&self, phase: &str) -> Result<(), Error> {
        if self.effects.join(format!("{phase}.done")).is_file() {
            Ok(())
        } else {
            Err(format!("{} requires completed {phase}", self.phase.name()).into())
        }
    }

    /// Whether this invocation is the supervisor's per-boot environment hook (`install`/`restart`
    /// reasons, run on every launch under a constant attempt id) rather than one update attempt.
    fn is_per_boot(&self) -> bool {
        matches!(self.reason.as_str(), "install" | "restart")
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

    fn deployment(root: PathBuf, phase: Phase, attempt: &str) -> Deployment {
        Deployment {
            phase,
            attempt: attempt.into(),
            candidate: "22.0.0".into(),
            predecessor: "1.0.0".into(),
            candidate_dir: root.join("candidate"),
            managed_pid: None,
            reason: "update".into(),
            state: root.clone(),
            effects: root.join("attempts").join(attempt),
            live: root.join("live"),
            backup: root.join("backups").join(attempt),
        }
    }

    #[test]
    fn cold_boot_start_does_not_require_an_update_activation() {
        let root = std::env::temp_dir().join(format!(
            "updated-demo-lifecycle-cold-boot-{}",
            std::process::id()
        ));
        let mut deployment = deployment(root.clone(), Phase::Apply, "boot");
        deployment.reason = "install".into();
        fs::create_dir_all(&deployment.live).unwrap();

        assert!(!deployment.effects.join("activate.done").exists());
        deployment.start().unwrap();
        expect(&deployment.live.join("application.war"), "22.0.0").unwrap();
        expect(
            &deployment.live.join("content.repository"),
            "schema=2 version=22.0.0 migrated=true",
        )
        .unwrap();
        required_file(&deployment.live.join("change-ticket.receipt")).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn steady_state_verification_does_not_require_transaction_markers() {
        let root = std::env::temp_dir().join(format!(
            "updated-demo-lifecycle-periodic-{}",
            std::process::id()
        ));
        let live = root.join("live");
        fs::create_dir_all(&live).unwrap();
        fs::write(
            live.join("content.repository"),
            b"schema=2 version=22.0.0 migrated=true\n",
        )
        .unwrap();
        fs::write(live.join("change-ticket.receipt"), b"complete\n").unwrap();
        let deployment = deployment(root.clone(), Phase::Healthcheck, "healthcheck");

        assert!(!deployment.effects.join("start.done").exists());
        assert!(!deployment.live.join("migration.plan").exists());
        deployment.validate_running_version("22.0.0\n").unwrap();
        expect(
            &deployment.live.join("content.repository"),
            "schema=2 version=22.0.0 migrated=true",
        )
        .unwrap();
        required_file(&deployment.live.join("change-ticket.receipt")).unwrap();

        fs::remove_dir_all(root).unwrap();
    }
}
