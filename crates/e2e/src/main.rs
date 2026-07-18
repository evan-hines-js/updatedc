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

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--lifecycle-fixture") {
        if let Err(error) = run_lifecycle_fixture() {
            eprintln!("lifecycle fixture: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(e) = run() {
        eprintln!("\x1b[1;31mFAIL: {e}\x1b[0m");
        std::process::exit(1);
    }
    println!("\n\x1b[1;32mSUCCESS: all scenarios passed\x1b[0m");
}

/// Cross-platform operator-lifecycle fixture. Every call is recorded, while a create-new
/// marker models an idempotent side effect that may happen only once per (transaction,
/// phase), even when crash recovery necessarily replays the command.
fn run_lifecycle_fixture() -> R {
    use std::io::Write;

    let root = std::env::args()
        .nth(2)
        .map(PathBuf::from)
        .ok_or("missing fixture state directory")?;
    let mode = std::env::args().nth(3).unwrap_or_default();
    let phase = std::env::var("UPDATED_LIFECYCLE_PHASE").map_err(|error| error.to_string())?;
    let id = std::env::var("UPDATED_LIFECYCLE_ATTEMPT_ID").map_err(|error| error.to_string())?;
    std::fs::create_dir_all(root.join("effects")).map_err(str_err)?;
    let mut attempts = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("attempts.log"))
        .map_err(str_err)?;
    writeln!(attempts, "{phase}\t{id}").map_err(str_err)?;

    let marker = root.join("effects").join(format!("{id}-{phase}"));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
    {
        Ok(mut file) => {
            writeln!(file, "{id}").map_err(str_err)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(str_err(error)),
    }
    if phase == "drain" {
        let fail_once = mode == "fail-first-drain"
            && std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(root.join("drain-failure-injected"))
                .is_ok();
        if mode == "fail-drain" || fail_once {
            return fail("injected drain failure");
        }
    }
    Ok(())
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
            "two nodes receive one group release; only the failing node rolls back",
            group_peer_failure_is_node_local,
        ),
        (
            "a tampered pinned root blocks updates but not the verified offline baseline",
            tampered_root_fails_closed,
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
        s.push((
            "an unexecutable reexec candidate is rejected without downtime; the next release upgrades",
            reexec_rejects_unexecutable_without_downtime,
        ));
        s.push((
            "a failed reexec preflight touches no live or durable activation state",
            reexec_preflight_rejects_without_activation,
        ));
    }
    // Chaos recovery runs last: it replays every transaction boundary, so it is by
    // far the slowest scenario.
    s.push((
        "crash at every update boundary; a fresh supervisor recovers",
        chaos_recovery,
    ));
    s.push((
        "crash before and after every rollback boundary; recovery remains resumable",
        rollback_chaos_recovery,
    ));
    s.push((
        "crash after an aborted drain does not replay completed lifecycle scripts",
        aborted_transition_chaos_recovery,
    ));
    s.push((
        "recovery keeps an attempt ID while a later retry receives a fresh one",
        transition_attempt_ids_are_scoped,
    ));
    s
}

fn run() -> R {
    let ctx = Ctx::new()?;
    step("build workspace binaries");
    ctx.build()?;
    // Build the two application versions once; scenarios reuse them.
    let app_v1 = ctx.build_app("1.0.0")?;
    let app_v2 = ctx.build_app("2.0.0")?;
    if sha256_hex(&app_v1) != sha256_hex(&app_v2) {
        return fail(
            "sample app binaries differ; release identity must come only from bundle config",
        );
    }
    let reexec_v1 = ctx.build_reexec_app("1.0.0")?;
    let reexec_v2 = ctx.build_reexec_app("2.0.0")?;
    if sha256_hex(&reexec_v1) != sha256_hex(&reexec_v2) {
        return fail("reexec sample binaries differ; release identity must come only from config");
    }
    // Two distinguishable supervisor builds for the self-update scenarios.
    ctx.build_supervisor("1.0.0")?;
    ctx.build_supervisor("2.0.0")?;

    // Every scenario owns a unique working dir and unique ports, so they are safe to
    // run concurrently on a bounded worker pool. They are blocking process work
    // (spawn, poll HTTP, sleep), not async I/O, so plain threads fit; an async runtime
    // would only wrap the same blocking work in a thread pool. Override the degree with
    // E2E_JOBS (E2E_JOBS=1 gives the old sequential order for debugging). The whole run
    // completes even when a scenario fails, so one run reports every failure.
    let mut scenarios = scenarios();
    if let Ok(filter) = std::env::var("E2E_FILTER") {
        scenarios.retain(|(name, _)| name.contains(&filter));
        if scenarios.is_empty() {
            return fail(format!("E2E_FILTER matched no scenarios: {filter}"));
        }
    }
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

#[cfg(unix)]
fn reexec_app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/reexec-app-{v}{}", ctx.exe))
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
    repository_base_url: String,
    supervisor_bin: PathBuf,
    server_bin: PathBuf,
    platform: String,
    exe: &'static str,
    guardian_bin: PathBuf,
    oneshot_bin: PathBuf,
    dir: PathBuf,
    product: String,
    install_root: PathBuf,
    seed_binary: PathBuf,
    args: Vec<String>,
    health_url: Option<String>,
    check_interval: Option<String>,
    health_grace: Option<String>,
    confirmation_window: Option<String>,
    lifecycle_command: Option<Vec<String>>,
    reexec: bool,
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
        let seed_binary = PathBuf::from(command.first().expect("app command requires binary"));
        Sup {
            root: ctx.root(dir),
            repository_base_url: format!("http://{srv}/"),
            supervisor_bin: ctx.supervisor.clone(),
            server_bin: ctx.server.clone(),
            platform: ctx.platkey.clone(),
            exe: ctx.exe,
            guardian_bin: ctx.bootstrap.clone(),
            oneshot_bin: ctx.oneshot.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            install_root: dir.join("install"),
            seed_binary,
            args: command.into_iter().skip(1).collect(),
            health_url: None,
            check_interval: None,
            health_grace: None,
            confirmation_window: None,
            lifecycle_command: None,
            reexec: false,
            supervisor_check_interval: None,
            ready_timeout: None,
            supervisor_override: None,
        }
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
    pub fn reexec(mut self, command: Vec<String>) -> Self {
        self.reexec = true;
        self.lifecycle_command = Some(command);
        self
    }
    pub fn lifecycle(mut self, command: Vec<String>) -> Self {
        self.lifecycle_command = Some(command);
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
        self.seed_install()?;
        let mut t = format!(
            "[routing]\nroot = {}\nbase_url = {}\nassignment = 'assignments/nodes/node.json'\n\n[repository]\nroot = {}\n\n[application]\nproduct = {}\ninstall_root = {}\nargs = [{}]\n",
            lit(&self.root.display().to_string()),
            lit(&self.repository_base_url),
            lit(&self.root.display().to_string()),
            lit(&self.product),
            lit(&self.install_root.display().to_string()),
            self.args.iter().map(|s| lit(s)).collect::<Vec<_>>().join(", "),
        );
        if let Some(u) = &self.health_url {
            t += &format!("health_url = {}\n", lit(u));
        }
        if let Some(c) = &self.lifecycle_command {
            let (program, provider_args) = c
                .split_first()
                .ok_or("lifecycle command requires an executable")?;
            let program = resolve_executable(program)?;
            let mut published_source = program.clone();
            let mut published_entrypoint = format!("bin/lifecycle{}", self.exe);
            let mut signed_args = provider_args.to_vec();
            #[cfg(unix)]
            if program.file_name().and_then(|name| name.to_str()) == Some("sh")
                && provider_args.first().map(String::as_str) == Some("-c")
                && provider_args.len() == 2
            {
                use std::os::unix::fs::PermissionsExt;
                let tree = self.dir.join("lifecycle-provider-source");
                published_entrypoint = "bin/lifecycle".into();
                published_source = tree.clone();
                std::fs::create_dir_all(tree.join("bin")).map_err(str_err)?;
                let entrypoint = tree.join(&published_entrypoint);
                std::fs::write(&entrypoint, format!("#!/bin/sh\n{}\n", provider_args[1]))
                    .map_err(str_err)?;
                let mut permissions = std::fs::metadata(&entrypoint)
                    .map_err(str_err)?
                    .permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(&entrypoint, permissions).map_err(str_err)?;
                signed_args.clear();
            }
            let provider_product = format!("{}-lifecycle", self.product);
            harness::run(
                Command::new(&self.server_bin)
                    .arg("publish-provider-artifact")
                    .arg("--repo")
                    .arg(self.dir.join("repo"))
                    .arg("--keys")
                    .arg(self.dir.join("keys"))
                    .args(["--product", &provider_product, "--version", "1.0.0"])
                    .arg("--bundle")
                    .arg(format!("{}={}", self.platform, published_source.display()))
                    .args(["--entrypoint", &published_entrypoint]),
            )?;
            let provider_path = harness::release_target(
                &provider_product,
                "stable",
                "1.0.0",
                &self.platform,
                &provider_product,
            );
            let provider_sha = sha256_hex(&self.dir.join("repo/targets").join(&provider_path));
            let mut provider_set = Command::new(&self.server_bin);
            provider_set
                .arg("publish-provider-set")
                .arg("--repo")
                .arg(self.dir.join("repo"))
                .arg("--keys")
                .arg(self.dir.join("keys"))
                .args(["--id", "default"])
                .args(["--provider-path", &provider_path])
                .args(["--provider-sha256", &provider_sha])
                .args(["--provider-timeout-ms", "5000"]);
            for arg in &signed_args {
                provider_set.args(["--provider-arg", arg]);
            }
            harness::run(&mut provider_set)?;
            republish_assignment(self, "provider-default")?;
            if self.reexec {
                t += "\n[application.activation]\nmode = \"reexec\"\n";
            }
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

    fn seed_install(&self) -> R {
        let paths = updated::config::Paths {
            install_root: self.install_root.clone(),
            versions: self.install_root.join("versions"),
            staging: self.install_root.join("staging"),
            active_release: self.install_root.join("active-release"),
            download: self.install_root.join("staging/bundle.download"),
            state: self.install_root.join("state/installed.json"),
            datastore: self.install_root.join("state/tuf"),
            routing_datastore: self.install_root.join("state/routing-tuf"),
            assignment: self.install_root.join("state/repository-assignment.json"),
            journal: self.install_root.join("state/transaction.json"),
            rejected: self.install_root.join("state/rejected"),
            app_token: self.install_root.join("state/app-token"),
            provider_versions: self.install_root.join("providers/versions"),
            provider_staging: self.install_root.join("providers/staging"),
            provider_download: self.install_root.join("providers/staging/bundle.download"),
        };
        if matches!(
            updated::state::read_installed(&paths.state),
            updated::state::Installed::Present(_)
        ) {
            return Ok(());
        }
        let prepared = self.install_root.join("seed-source");
        std::fs::create_dir_all(prepared.join("bin")).map_err(str_err)?;
        std::fs::create_dir_all(prepared.join("config")).map_err(str_err)?;
        let entrypoint = format!("bin/app{}", if cfg!(windows) { ".exe" } else { "" });
        std::fs::copy(&self.seed_binary, prepared.join(&entrypoint)).map_err(str_err)?;
        std::fs::write(
            prepared.join("config/release.toml"),
            "version = \"1.0.0\"\n",
        )
        .map_err(str_err)?;
        std::fs::create_dir_all(self.install_root.join("state")).map_err(str_err)?;
        updated::bundle::create_bundle(
            &prepared,
            &paths.download,
            &self.product,
            "1.0.0",
            &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            &entrypoint,
        )
        .map_err(str_err)?;
        let staged = updated::provider::BundleStore::for_app(&paths)
            .install(
                &paths.download,
                &updated::bundle::ExpectedBundle {
                    product: &self.product,
                    version: "1.0.0",
                    platform: &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                },
            )
            .map_err(str_err)?;
        updated::bundle::write_active(&paths.active_release, &staged.id).map_err(str_err)?;
        updated::state::write_installed(
            &paths.state,
            &updated::state::InstalledState::confirmed(staged.id, staged.archive_sha256),
        )
        .map_err(str_err)
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

fn republish_assignment(sup: &Sup, deployment: &str) -> R {
    let desired = std::fs::read_to_string(sup.dir.join("desired-app")).map_err(str_err)?;
    let mut desired = desired.lines();
    let app_path = desired
        .next()
        .ok_or("desired application path is missing")?;
    let app_sha = desired
        .next()
        .ok_or("desired application hash is missing")?;
    let set_path = "provider-sets/default.json";
    let set_sha = sha256_hex(&sup.dir.join("repo/targets").join(set_path));
    harness::run(
        Command::new(&sup.server_bin)
            .arg("publish-assignment")
            .arg("--repo")
            .arg(sup.dir.join("repo"))
            .arg("--keys")
            .arg(sup.dir.join("keys"))
            .args(["--name", "assignments/nodes/node.json"])
            .args([
                "--metadata-url",
                &format!("{}metadata/", sup.repository_base_url),
            ])
            .args([
                "--targets-url",
                &format!("{}targets/", sup.repository_base_url),
            ])
            .args(["--deployment", deployment])
            .args(["--application-path", app_path])
            .args(["--application-sha256", app_sha])
            .args(["--provider-set-path", set_path])
            .args(["--provider-set-sha256", &set_sha]),
    )
}

fn resolve_executable(program: &str) -> R<PathBuf> {
    let path = PathBuf::from(program);
    if path.components().count() > 1 {
        return Ok(path);
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("lifecycle executable {program:?} was not found on PATH"))
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
