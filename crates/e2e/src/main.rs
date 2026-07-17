//! End-to-end test / demo. One cross-platform Rust binary — instead of parallel
//! bash and PowerShell scripts that inevitably drift — that builds the release
//! binaries, stands up a real TUF repository via the `server`, and drives real
//! application-update, rollback, supervisor self-update, crash-recovery, and
//! TUF/hardening scenarios against them. Platform-specific behaviour lives behind
//! `#[cfg(...)]`, not in a second script.
//!
//! Run: `cargo run -p e2e`. Exit 0 means every scenario passed. Scenarios are
//! independent (unique dirs + ports) and run on a bounded thread pool; set
//! `E2E_JOBS=1` to run them one at a time in order.

mod harness;
mod scenarios;

use harness::*;
use scenarios::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
// The tower's own path-suffix helper — the same one resolve_paths derives its
// sibling paths with — so the scenarios name on-disk files exactly as the product does.
use updated::config::with_suffix;

fn main() {
    if let Err(e) = run() {
        eprintln!("\x1b[1;31mFAIL: {e}\x1b[0m");
        std::process::exit(1);
    }
    println!("\n\x1b[1;32mSUCCESS: all scenarios passed\x1b[0m");
}

/// A named scenario. To add one: write an `fn(&Ctx) -> R` that asserts its own
/// behaviour (returning `Err` on failure), then add a line to `scenarios()`.
type Scenario = (&'static str, fn(&Ctx) -> R);

fn scenarios() -> Vec<Scenario> {
    #[allow(unused_mut)]
    let mut s: Vec<Scenario> = vec![
        (
            "application upgrade v1->v2, then rollback of a broken v3",
            app_update_and_rollback,
        ),
        (
            "a committed update that crashes after health is reverted + rejected (one strike)",
            app_post_health_crash_reverts,
        ),
        (
            "a tampered pinned root blocks updates but not the verified offline baseline",
            tampered_root_fails_closed,
        ),
        (
            "a tampered first-install binary is rejected before execution",
            tampered_first_install_fails_closed,
        ),
        (
            "a drifted on-disk binary is refused at startup",
            drift_fail_closed,
        ),
        (
            "a second supervisor on the same install is refused",
            single_instance_lock,
        ),
        (
            "a health-check-failed release stays rejected across a restart",
            persisted_rejection,
        ),
        (
            "a supervisor crash does not disturb the app; the guardian relaunches it",
            supervisor_crash_preserves_app,
        ),
        (
            "a clean stop (SIGTERM to the guardian) reaps the whole tower — no orphans",
            clean_stop_reaps_the_whole_tower,
        ),
        (
            "the supervisor self-updates by pointer flip; the app never restarts",
            supervisor_self_update,
        ),
        (
            "an unlaunchable supervisor candidate is rolled back, rejected, and never retried",
            supervisor_self_update_rollback,
        ),
        (
            "updated-oneshot updates a non-daemon program to the newest release on launch",
            oneshot_updates_on_launch,
        ),
        (
            "updated-oneshot launches the current version when the repository is unreachable",
            oneshot_launches_without_repository,
        ),
    ];
    // Unix-only mechanisms (file modes; fork/exec/signals for zero-downtime).
    #[cfg(unix)]
    {
        s.push(("the TUF role keys are owner-only (0600)", key_perms));
        s.push((
            "zero-downtime reexec reload drops no requests under load",
            zero_downtime_reexec,
        ));
    }
    // Chaos recovery runs last: it replays every transaction boundary, so it is by
    // far the slowest scenario.
    s.push((
        "crash at every update boundary; a fresh supervisor recovers",
        chaos_recovery,
    ));
    s
}

fn run() -> R {
    let ctx = Ctx::new()?;
    step("build workspace binaries");
    ctx.build()?;
    // Build the two application versions once; scenarios reuse them.
    ctx.build_app("1.0.0")?;
    ctx.build_app("2.0.0")?;
    // Two distinguishable supervisor builds for the self-update scenarios.
    ctx.build_supervisor("1.0.0")?;
    ctx.build_supervisor("2.0.0")?;

    // Every scenario owns a unique working dir and unique ports, so they are safe to
    // run concurrently on a bounded worker pool. They are blocking process work
    // (spawn, poll HTTP, sleep), not async I/O, so plain threads fit; an async runtime
    // would only wrap the same blocking work in a thread pool. Override the degree with
    // E2E_JOBS (E2E_JOBS=1 gives the old sequential order for debugging). The whole run
    // completes even when a scenario fails, so one run reports every failure.
    let scenarios = scenarios();
    let n = scenarios.len();
    let jobs = job_count(n);
    step(&format!("running {n} scenarios, up to {jobs} at a time"));

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(&'static str, R)>> = Mutex::new(Vec::new());
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(&(name, scenario)) = scenarios.get(i) else {
                    break;
                };
                let began = Instant::now();
                // A panicking scenario becomes a failure, not an aborted run.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenario(&ctx)))
                    .unwrap_or_else(|_| fail("scenario panicked"));
                let secs = began.elapsed().as_secs_f64();
                match &res {
                    Ok(()) => println!("\x1b[1;32mPASS\x1b[0m ({secs:>5.1}s) {name}"),
                    Err(e) => println!("\x1b[1;31mFAIL\x1b[0m ({secs:>5.1}s) {name}: {e}"),
                }
                results.lock().unwrap().push((name, res));
            });
        }
    });

    let results = results.into_inner().unwrap();
    let failures: Vec<&str> = results
        .iter()
        .filter_map(|(name, r)| r.is_err().then_some(*name))
        .collect();
    println!(
        "\n{} of {n} scenarios passed in {:.1}s",
        n - failures.len(),
        start.elapsed().as_secs_f64()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} scenario(s) failed: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

/// Degree of parallelism: `E2E_JOBS` when set (clamped to at least 1), else the
/// machine's parallelism capped at four so a run does not massively oversubscribe —
/// each scenario itself spawns a handful of processes. Never more than the scenario
/// count.
fn job_count(n: usize) -> usize {
    let n = n.max(1);
    if let Ok(Ok(j)) = std::env::var("E2E_JOBS").map(|v| v.parse::<usize>()) {
        return j.clamp(1, n);
    }
    let cpus = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);
    default_job_count(n, cpus)
}

fn default_job_count(scenarios: usize, cpus: usize) -> usize {
    scenarios.max(1).min(cpus.max(1)).min(4)
}

fn step(msg: &str) {
    println!("\n\x1b[1;36m== {msg} ==\x1b[0m");
}
fn ok(msg: &str) {
    println!("\x1b[1;32m{msg}\x1b[0m");
}

fn app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/app-{v}{}", ctx.exe))
}

fn supervisor_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/supervisor-{v}{}", ctx.exe))
}

/// The managed-app command line (binary path + args) for a scenario config.
fn appcmd(app: &Path, args: &[&str]) -> Vec<String> {
    let mut v = vec![app.display().to_string()];
    v.extend(args.iter().map(|s| s.to_string()));
    v
}

/// A TOML literal string (single-quoted, no escaping) — safe for Windows paths.
fn lit(s: &str) -> String {
    format!("'{s}'")
}

/// Writes a scenario's config file and yields a guardian command — the whole tower.
/// The guardian (`bootstrap`) launches the disposable supervisor, which owns the update
/// policy and drives the guardian to run the application. Production launches nothing
/// else; there is no way to run the supervisor standalone.
pub struct Sup {
    root: PathBuf,
    meta_url: String,
    targets_url: String,
    supervisor_bin: PathBuf,
    guardian_bin: PathBuf,
    oneshot_bin: PathBuf,
    dir: PathBuf,
    product: String,
    current_version: String,
    current_sha256: String,
    command: Vec<String>,
    health_url: Option<String>,
    check_interval: Option<String>,
    health_grace: Option<String>,
    confirmation_window: Option<String>,
    reload_command: Option<Vec<String>>,
    supervisor_check_interval: Option<String>,
    ready_timeout: Option<String>,
    /// Override the supervisor binary the guardian runs (self-update tests supply a
    /// specific version); defaults to the built one.
    supervisor_override: Option<PathBuf>,
}

impl Sup {
    /// The tower managing `command` (the app binary + args) against the repo under
    /// `dir` served at `srv`, for `product`.
    pub fn new(ctx: &Ctx, dir: &Path, srv: &str, product: &str, command: Vec<String>) -> Self {
        let current_sha256 = command
            .first()
            .map(|path| sha256_hex(Path::new(path)))
            .unwrap_or_default();
        Sup {
            root: ctx.root(dir),
            meta_url: ctx.meta_url(srv),
            targets_url: ctx.targets_url(srv),
            supervisor_bin: ctx.supervisor.clone(),
            guardian_bin: ctx.bootstrap.clone(),
            oneshot_bin: ctx.oneshot.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            current_version: "1.0.0".into(),
            current_sha256,
            command,
            health_url: None,
            check_interval: None,
            health_grace: None,
            confirmation_window: None,
            reload_command: None,
            supervisor_check_interval: None,
            ready_timeout: None,
            supervisor_override: None,
        }
    }
    pub fn baseline_sha256(mut self, sha256: String) -> Self {
        self.current_sha256 = sha256;
        self
    }
    pub fn health(mut self, svc: &str) -> Self {
        self.health_url = Some(format!("http://{svc}/healthz"));
        self
    }
    pub fn check_interval(mut self, s: &str) -> Self {
        self.check_interval = Some(s.into());
        self
    }
    pub fn health_grace(mut self, s: &str) -> Self {
        self.health_grace = Some(s.into());
        self
    }
    pub fn confirmation_window(mut self, s: &str) -> Self {
        self.confirmation_window = Some(s.into());
        self
    }
    pub fn reload(mut self, command: Vec<String>) -> Self {
        self.reload_command = Some(command);
        self
    }
    pub fn supervisor_check_interval(mut self, check_interval: &str) -> Self {
        self.supervisor_check_interval = Some(check_interval.into());
        self
    }
    /// How long a replacement supervisor has to prove ready before the guardian rolls back.
    pub fn ready_timeout(mut self, secs: &str) -> Self {
        self.ready_timeout = Some(secs.into());
        self
    }
    /// Run this supervisor binary instead of the default (self-update tests).
    pub fn supervisor_bin(mut self, path: &Path) -> Self {
        self.supervisor_override = Some(path.to_path_buf());
        self
    }

    /// The guardian's state directory for this scenario.
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("guardian-state")
    }

    fn write_config(&self) -> R<PathBuf> {
        let mut t = format!(
            "[repository]\nroot = {}\nmetadata_url = {}\ntargets_url = {}\n\n[application]\nproduct = {}\ncurrent_version = {}\ncurrent_sha256 = {}\ncommand = [{}]\n",
            lit(&self.root.display().to_string()),
            lit(&self.meta_url),
            lit(&self.targets_url),
            lit(&self.product),
            lit(&self.current_version),
            lit(&self.current_sha256),
            self.command.iter().map(|s| lit(s)).collect::<Vec<_>>().join(", "),
        );
        if let Some(u) = &self.health_url {
            t += &format!("health_url = {}\n", lit(u));
        }
        if let Some(c) = &self.reload_command {
            t += &format!(
                "reload_command = [{}]\n",
                c.iter().map(|arg| lit(arg)).collect::<Vec<_>>().join(", ")
            );
        }
        let mut to = String::new();
        for (k, v) in [
            ("check_interval", &self.check_interval),
            ("health_grace", &self.health_grace),
            ("confirmation_window", &self.confirmation_window),
            ("supervisor_check_interval", &self.supervisor_check_interval),
        ] {
            if let Some(v) = v {
                to += &format!("{k} = {}\n", lit(v));
            }
        }
        if !to.is_empty() {
            t += &format!("\n[timeouts]\n{to}");
        }
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let path = self.dir.join(format!(
            "config-{}.toml",
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, t).map_err(str_err)?;
        Ok(path)
    }

    /// A guardian command: `bootstrap --state-dir <dir> --supervisor-config <cfg>
    /// --supervisor <supervisor>`. This is the whole tower — the guardian owns the app,
    /// launches the supervisor, and reflects the app's exit code.
    pub fn guardian(self) -> R<Command> {
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        let supervisor = self
            .supervisor_override
            .clone()
            .unwrap_or_else(|| self.supervisor_bin.clone());
        let ready_timeout = self.ready_timeout.clone().unwrap_or_else(|| "30".into());
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.guardian_bin);
        c.arg("--state-dir")
            .arg(&state_dir)
            .arg("--supervisor-config")
            .arg(&cfg)
            .arg("--supervisor")
            .arg(&supervisor)
            .arg("--ready-timeout")
            .arg(&ready_timeout);
        Ok(c)
    }

    /// A one-shot updater command (`updated-oneshot --config <written file>`). Shares
    /// the exact same config the supervisor reads.
    pub fn oneshot(self) -> R<Command> {
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.oneshot_bin);
        c.arg("--config").arg(cfg);
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::default_job_count;

    #[test]
    fn default_e2e_parallelism_is_bounded_by_scenarios_cpus_and_four() {
        assert_eq!(default_job_count(16, 12), 4);
        assert_eq!(default_job_count(16, 2), 2);
        assert_eq!(default_job_count(3, 12), 3);
        assert_eq!(default_job_count(0, 0), 1);
    }
}
