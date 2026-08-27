//! The one node reconciler every scenario runs — and the reference implementation of a hook that
//! OWNS a workload process.
//!
//! The agent is a package runner: it never launches, adopts, signals, or holds a workload. This
//! fixture is the other half of that contract. In `workload` mode its `apply` converges the sample
//! application onto the release it is pointed at, its `rollback` converges back onto the restored
//! predecessor, and its `healthcheck` observes the running workload — so every scenario that needs a
//! live service gets one from the release's own hook, exactly as an operator's script would.
//!
//! Two properties the execution contract demands, and this fixture demonstrates:
//!
//! * **Convergence, not restart.** `apply` leaves an already-correct workload alone (same release,
//!   same environment, still running). That is what makes a workload's PID provably stable across
//!   agent boots, restarts, crashes and self-updates — the agent has no means to disturb it, and
//!   its own reconciler does not either unless something actually changed.
//! * **Idempotence keyed to the attempt.** Every operation is recorded, and the migration adapter —
//!   the fixture's one genuinely one-way effect — inspects what is already on disk before doing its
//!   destructive half, so a crash-replayed invocation converges instead of clobbering its own
//!   restore point.
//!
//! One recording chokepoint sits ahead of every mode, so no mode can answer an operation that the
//! recorded history does not show.

use crate::harness::{fail, http_text, pid_alive, str_err, R};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use updated_contracts::reconciler::{Operation, Reason};

/// The provider argument that selects this fixture, followed by its state root and its mode.
pub const FLAG: &str = "--lifecycle-fixture";

/// The version every failure-injecting mode targets: the forward candidate a scenario publishes
/// over its 1.0.0 baseline. A rollback reverses the candidate/predecessor variables, so keying the
/// injection to this version leaves the recovery path free to restore the predecessor.
const FORWARD_CANDIDATE: &str = "2.0.0";

/// Whether this process was invoked as the reconciler fixture rather than as its own driver. Both
/// drivers that publish this binary as a provider (the scenario runner and the kill fuzzer) must
/// dispatch on it, or every hook invocation re-enters a whole nested run.
pub fn is_invocation(args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> bool {
    args.into_iter().any(|arg| arg.as_ref() == FLAG)
}

/// Run the reconciler fixture if this process was invoked as one, reporting whether it did.
///
/// Every binary that signs ITSELF in as a release's reconciler — the e2e driver, killfuzz — must
/// call this before anything else: the agent invokes the executable as the hook that owns the
/// workload, so a binary that fell through to its own `main` would recursively start a whole nested
/// suite on every hook call, which the agent then times out. That is one rule about how these
/// executables behave, so it is written once; a second binary copying the preamble is a binary that
/// can copy it slightly wrong, and the symptom is a timeout nobody reads as recursion.
///
/// Returns `true` when it handled the invocation, and the caller must then return from `main`
/// rather than exiting here: a fixture mode answers the agent on stdout and some modes deliberately
/// hang, so normal shutdown — flushes and destructors included — has to stay the caller's.
#[must_use = "when this returns true the process was a reconciler invocation and main must return"]
pub fn dispatch_if_invoked() -> bool {
    if !is_invocation(std::env::args_os()) {
        return false;
    }
    if let Err(error) = run() {
        eprintln!("node reconciler fixture: {error}");
        std::process::exit(1);
    }
    true
}

/// The fixture's state root for a scenario directory. One location, so a scenario and the provider
/// command it publishes can never disagree about where the recorded history lives.
pub fn root(dir: &Path) -> PathBuf {
    dir.join("lifecycle-fixture")
}

/// One recorded reconciler invocation, parsed back out of `operations.log`.
///
/// The operation and the reason are the published vocabulary, not strings: `Reason`'s own doc names
/// "a conformance harness, a test fixture" as the second speller it exists to prevent, and a
/// scenario comparing against its own literals would go on passing — or start failing for the wrong
/// reason — through a renamed spelling.
pub struct Invocation {
    pub operation: Operation,
    pub id: String,
    pub reason: Reason,
}

/// Every invocation the fixture under `root` has observed, oldest first.
pub fn operations(root: &Path) -> Vec<Invocation> {
    std::fs::read_to_string(root.join("operations.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let operation: Operation = fields.next()?.parse().ok()?;
            let id = fields.next()?.to_string();
            let reason: Reason = fields.next()?.parse().ok()?;
            // The recorded candidate version is for a human reading a failed run's log and is not
            // part of the assertion shape. Requiring it still rejects truncated records.
            fields.next()?;
            Some(Invocation {
                operation,
                id,
                reason,
            })
        })
        .collect()
}

/// The deployment operations recorded under transaction identities, as `(operation, attempt id)`
/// pairs. Operations carrying a reserved non-transaction attempt identity never appear here.
pub fn attempts(root: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(root.join("attempts.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            line.split_once('\t')
                .map(|(operation, id)| (operation.to_string(), id.to_string()))
        })
        .collect()
}

/// The distinct TRANSACTIONS behind a recorded attempt history. A transaction's forward direction
/// carries its own token and its compensating direction carries that token plus a trailing `r`
/// (never a hex digit, so the mapping is exact); both fold to the one transaction they belong to.
/// This is what a scenario asserts on when it means "no retry under a new identity" — a
/// compensation is the same transaction, not a second one.
pub fn transactions(attempts: &[(String, String)]) -> std::collections::BTreeSet<String> {
    attempts
        .iter()
        .map(|(_, id)| id.strip_suffix('r').unwrap_or(id).to_string())
        .collect()
}

/// The invocations recorded after `since` that no agent-only event may ever produce: any deployment
/// operation (a non-reserved attempt id) and any `rollback`. An agent legitimately runs
/// `apply`/`healthcheck` under `boot`, another pair under `converge`, and steady observations under
/// `periodic`/`fingerprint`; a deployment or a rollback means it reached for the workload.
pub fn disturbances(root: &Path, since: usize) -> Vec<String> {
    operations(root)
        .into_iter()
        .skip(since)
        .filter(|invocation| {
            !updated_contracts::reconciler::attempt::is_reserved(&invocation.id)
                || invocation.operation == Operation::Rollback
        })
        .map(|invocation| {
            format!(
                "{} under {} ({})",
                invocation.operation, invocation.id, invocation.reason
            )
        })
        .collect()
}

// ------------------------------------ modes ---------------------------------------

/// What the fixture does beyond recording. Modes compose: a comma-separated list of directives, so
/// one scenario can manage a workload *and* inject a failure into a phase without a second fixture.
#[derive(Default)]
struct Mode {
    /// Manage the sample application at this address.
    workload: Option<String>,
    /// A `--fault` to launch the workload with.
    fault: Option<String>,
    /// How long the hook withdraws the workload from traffic before stopping it, for a release that
    /// sits behind a load balancer. Draining is the hook's job — the agent has no workload to
    /// withdraw — so a scenario that cares about in-flight requests asks for it here. Unset means
    /// the release publishes no rotation signal at all, which is what every other scenario models.
    drain: Option<Duration>,
    /// Operations that exit non-zero.
    fail: Vec<Operation>,
    /// The operation that wedges past every hook timeout.
    hang: Option<Operation>,
    migration: Migration,
}

/// The migration-shaped adapter's stateful behaviour: a slow-starting stateful application whose
/// upgrade runs a one-way content migration, with a backup taken first so a failed migration can be
/// restored.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Migration {
    #[default]
    Off,
    /// Every candidate runs the adapter.
    On,
    /// The adapter runs but its migration fails after writing, so rollback must restore the backup.
    FailApply,
    /// Only the migration-shaped candidate runs the adapter; the ordinary release after it returns
    /// to the generic path.
    Transition,
}

impl Migration {
    /// The healthcheck gate applies to every migration-shaped mode: a probe that lands before the
    /// migration finalized is a contract violation, not a slow start.
    fn gates_health(self) -> bool {
        self != Migration::Off
    }

    fn runs_adapter(self, candidate_version: &str) -> bool {
        match self {
            Migration::Off => false,
            Migration::Transition => candidate_version == FORWARD_CANDIDATE,
            Migration::On | Migration::FailApply => true,
        }
    }
}

impl Mode {
    fn parse(text: &str) -> R<Mode> {
        let mut mode = Mode::default();
        for directive in text.split(',').filter(|part| !part.is_empty()) {
            let (key, value) = match directive.split_once('=') {
                Some((key, value)) => (key, Some(value)),
                None => (directive, None),
            };
            let operation = |value: Option<&str>| -> R<Operation> {
                value
                    .ok_or_else(|| format!("fixture directive {key} needs an operation"))?
                    .parse()
                    .map_err(str_err)
            };
            match key {
                // The default: record and succeed. Named so a mode is never an empty argument.
                "inert" => {}
                "workload" => {
                    mode.workload = Some(
                        value
                            .ok_or("fixture directive workload needs an address")?
                            .to_string(),
                    )
                }
                "fault" => {
                    mode.fault = Some(
                        value
                            .ok_or("fixture directive fault needs a name")?
                            .to_string(),
                    )
                }
                "drain" => {
                    mode.drain = Some(Duration::from_millis(
                        value
                            .ok_or("fixture directive drain needs milliseconds")?
                            .parse()
                            .map_err(str_err)?,
                    ))
                }
                "fail" => mode.fail.push(operation(value)?),
                "hang" => mode.hang = Some(operation(value)?),
                "migration-shaped" => mode.migration = Migration::On,
                "migration-shaped-fail-apply" => mode.migration = Migration::FailApply,
                "migration-shaped-transition" => mode.migration = Migration::Transition,
                other => return fail(format!("unknown fixture directive {other:?}")),
            }
        }
        Ok(mode)
    }

    /// Whether this invocation is one of the injected failures. Forward operations fail only for
    /// the forward candidate, so the recovery that follows can still restore the predecessor; a
    /// `rollback` failure is unconditional — it is how a durably-held failed recovery is proven.
    fn fails(&self, operation: Operation, candidate_version: &str) -> bool {
        self.fail.contains(&operation)
            && (operation == Operation::Rollback || candidate_version == FORWARD_CANDIDATE)
    }
}

// ---------------------------------- invocation ------------------------------------

/// Run one reconciler invocation. Called from a driver's `main` when [`is_invocation`] holds.
pub fn run() -> R {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let operation: Operation = args
        .first()
        .ok_or("missing reconciler operation")?
        .parse()
        .map_err(str_err)?;
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or("missing reconciler/provider argument separator")?;
    let value = |name: &str| -> R<String> {
        let index = args[..separator]
            .iter()
            .position(|arg| arg == name)
            .ok_or_else(|| format!("missing {name}"))?;
        args.get(index + 1)
            .cloned()
            .ok_or_else(|| format!("missing value for {name}"))
    };
    if value("--protocol")? != "1" {
        return fail("unsupported reconciler protocol");
    }
    let id = value("--attempt-id")?;
    let reason = value("--reason")?;
    let candidate = PathBuf::from(value("--candidate")?);
    let candidate_version = value("--candidate-version")?;
    let result_file = PathBuf::from(value("--result-file")?);
    let provider_args = &args[separator + 1..];
    let at = provider_args
        .iter()
        .position(|arg| arg == FLAG)
        .ok_or("missing --lifecycle-fixture")?;
    let root = provider_args
        .get(at + 1)
        .map(PathBuf::from)
        .ok_or("missing fixture state directory")?;
    let mode = Mode::parse(provider_args.get(at + 2).map_or("", String::as_str))?;

    // The one recording chokepoint, ahead of every mode: nothing below may answer an operation
    // that this did not observe.
    record(&root, operation, &id, &reason, &candidate_version)?;

    // Inspect is a steady-state observation, not a deployment transaction: deterministic
    // fingerprint material, no modeled side effect.
    if operation == Operation::Inspect {
        println!("candidate-version={candidate_version}");
        return Ok(());
    }

    // A hook that wedges rather than exiting non-zero must be bounded by the agent's hook timeout.
    // Sleep far past it so the agent kills this tree.
    if mode.hang == Some(operation) && candidate_version == FORWARD_CANDIDATE {
        std::thread::sleep(Duration::from_secs(30));
    }
    // Injected failures answer before any effect, so a contained failure never leaves the candidate
    // half-applied.
    if mode.fails(operation, &candidate_version) {
        return fail(format!("injected {} failure", operation.as_str()));
    }

    if mode.migration.runs_adapter(&candidate_version) {
        migrate(&root, mode.migration, operation, &id, &candidate_version)?;
    }
    if mode.migration.gates_health() && operation == Operation::Healthcheck {
        migration_gate(&root, &candidate_version)?;
    }

    let outcome = match mode.workload.as_deref() {
        None => Ok(()),
        // `--candidate` is the release to converge ONTO in both directions: on a rollback the agent
        // passes the release being restored as the candidate and the failed one as the predecessor,
        // so a hook that converges toward `--candidate` needs no direction-specific branch at all.
        Some(address) if operation.mutation().is_some() => {
            converge(&root, &candidate, address, &mode)
        }
        Some(address) if operation == Operation::Healthcheck => {
            probe(address)?;
            // A healthy observation is also the answer to "is this node fit to serve": a workload
            // that came up after its `apply` stopped waiting rejoins rotation here.
            restore_rotation(&root, address, &mode)
        }
        Some(_) => Ok(()),
    };
    outcome?;
    if operation.mutation().is_some() {
        let result = updated_contracts::reconciler::ResultDocument::succeeded(
            true,
            updated_contracts::reconciler::HostAction::None,
            None,
        )
        .map_err(str_err)?;
        foundation::durable::atomic_write(
            &result_file,
            ".result-",
            &result.to_bounded_json().map_err(str_err)?,
        )
        .map_err(str_err)?;
    }
    Ok(())
}

/// Record one invocation. This is the fixture's only writer of observation history.
///
/// `operations.log` holds every invocation, including the reserved identities, with its stable
/// operation identity. `attempts.log` holds only deployment operations, so it is the transaction
/// history alone. The cleared process environment is deliberately absent: configuration has only
/// the file-native input path, and recording another representation would revive the old model.
fn record(root: &Path, operation: Operation, id: &str, reason: &str, version: &str) -> R {
    let append = |path: PathBuf, line: &str| -> R {
        std::fs::create_dir_all(root).map_err(str_err)?;
        let mut log = foundation::file::open_append_file(&path).map_err(str_err)?;
        writeln!(log, "{line}").map_err(str_err)
    };
    append(
        root.join("operations.log"),
        &format!("{}\t{id}\t{reason}\t{version}", operation.as_str()),
    )?;
    if updated_contracts::reconciler::attempt::is_reserved(id) {
        return Ok(());
    }
    append(
        root.join("attempts.log"),
        &format!("{}\t{id}", operation.as_str()),
    )?;
    Ok(())
}

// ---------------------------------- the workload ----------------------------------

/// The workload's recorded identity. `apply` compares the running release so an already-correct
/// workload is left strictly alone — the difference between convergence and restarting a healthy
/// service on every boot. Configuration identity is not duplicated here: a real reconciler
/// compares its managed files/state, while the fixture's workload consumes no assigned inputs.
#[derive(serde::Serialize, serde::Deserialize)]
struct WorkloadRecord {
    pid: u32,
    release: String,
}

fn record_path(root: &Path) -> PathBuf {
    root.join("workload.json")
}

fn read_workload(root: &Path) -> Option<WorkloadRecord> {
    serde_json::from_slice(&std::fs::read(record_path(root)).ok()?).ok()
}

/// Converge the workload onto `release`: leave it alone if it already runs these bytes under this
/// fixture-managed state, otherwise withdraw it from traffic, stop it, and start the release's
/// entrypoint.
fn converge(root: &Path, release: &Path, address: &str, mode: &Mode) -> R {
    let release_id = release.display().to_string();
    let replacing = match read_workload(root) {
        Some(current) if current.release == release_id && pid_alive(current.pid) => {
            // Already converged. Rotation is still derived rather than assumed: a workload that
            // came up after a previous `apply` gave up waiting is put back in rotation here.
            return restore_rotation(root, address, mode);
        }
        Some(current) => Some(current.pid),
        None => None,
    };
    // Withdraw before stopping, never after: a load balancer that is still routing to this node
    // when its process goes away drops the requests already in flight. The marker is the hook's
    // rotation signal, and it stays up until the replacement answers. One site sets it, mirroring
    // the one site that clears it.
    if let Some(hold) = mode.drain {
        drain_marker(root, true)?;
        if replacing.is_some() {
            std::thread::sleep(hold);
        }
    }
    if let Some(pid) = replacing {
        stop_pid(pid);
    }
    let program = release.join(format!("bin/app{}", std::env::consts::EXE_SUFFIX));
    let mut command = Command::new(&program);
    // The sample application resolves its release identity from `config/release.toml` beside its
    // entrypoint, so the release directory is its working directory.
    command.current_dir(release).args(["--addr", address]);
    if let Some(fault) = mode.fault.as_deref() {
        command.args(["--fault", fault]);
    }
    let log = foundation::file::open_append_file(&root.join("workload.log")).map_err(str_err)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().map_err(str_err)?))
        .stderr(Stdio::from(log));
    // The workload refuses to serve until the record names its own pid, and the stale record is
    // removed first, so no process capable of binding the service address can exist without a
    // durable reap handle naming it — this hook can be killed at any instant between the spawn and
    // the write, and the workload it started outlives every tree the node stack owns.
    command.args(["--await-record", &record_path(root).display().to_string()]);
    let _ = std::fs::remove_file(record_path(root));
    detach(&mut command);
    let child = command
        .spawn()
        .map_err(|error| format!("starting {}: {error}", program.display()))?;
    let workload = WorkloadRecord {
        pid: child.id(),
        release: release_id,
    };
    // Renamed into place, never truncate-then-write: a kill mid-write would otherwise leave an
    // unparseable record and the same unreapable orphan.
    foundation::durable::atomic_write(
        &record_path(root),
        ".workload-",
        &serde_json::to_vec(&workload).map_err(str_err)?,
    )
    .map_err(str_err)?;
    if mode.drain.is_none() {
        // Without a rotation signal there is nothing to wait for: `healthcheck` is the agent's only
        // health source, and an `apply` that probed here would consume an observation the release
        // may only be able to answer once.
        return Ok(());
    }
    // Back into rotation only once the replacement answers. A bound keeps `apply` inside its hook
    // timeout; a workload slower than the bound simply stays withdrawn until the next observation
    // finds it healthy — every `healthcheck` and every later `apply` restores rotation — so the
    // marker can never outlive the condition it describes.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        restore_rotation(root, address, mode)?;
        if !root.join("draining").is_file() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Put the node back in rotation if — and only if — the workload is answering. The one place the
/// rotation signal is cleared, so no path can leave a healthy node withdrawn.
fn restore_rotation(root: &Path, address: &str, mode: &Mode) -> R {
    if mode.drain.is_none() || probe(address).is_err() {
        return Ok(());
    }
    drain_marker(root, false)
}

/// The hook's readiness signal for a readiness-aware load balancer: present means "do not route
/// here". Publishing it beside the recorded history keeps it observable to a scenario without the
/// agent having any part in it.
fn drain_marker(root: &Path, draining: bool) -> R {
    let path = root.join("draining");
    if draining {
        return std::fs::write(path, b"draining\n").map_err(str_err);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(str_err(error)),
    }
}

/// Whether the fixture under `dir` is currently withdrawing its workload from traffic.
pub fn draining(dir: &Path) -> bool {
    root(dir).join("draining").is_file()
}

/// Detach the workload from this hook invocation, as the Invocation section of
/// `docs/node-reconciler-protocol.md` requires: a workload left inside the invocation's contained
/// tree is killed by its own successful `apply`.
fn detach(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the forked child before exec and calls only
        // async-signal-safe functions. The child is not a group leader (its parent is), so
        // `setsid` establishes a fresh session outside the agent's contained tree.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
        };
        command.creation_flags(
            CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
        );
    }
}

/// Observe the running workload — one bounded readiness observation, no side effects.
fn probe(address: &str) -> R {
    match http_text(&format!("http://{address}/healthz")) {
        Some(_) => Ok(()),
        None => fail(format!("the workload at {address} is not healthy")),
    }
}

/// Ask a pid to stop, escalating if it does not, and wait for the address it held to be released so
/// the next start can bind.
///
/// A pid the fixture recorded is routinely already gone — the workload runs outside every tree this
/// process owns, so nothing pins its slot and the number is reusable. Every signal is therefore
/// gated on a fresh liveness observation taken immediately before it: the residual window (the
/// process exits between the check and the signal) is inherent to pid-addressed signalling and is
/// microseconds wide, where an unguarded signal was seconds wide and aimed at a number a sibling
/// scenario may already own.
fn stop_pid(pid: u32) {
    if !pid_alive(pid) {
        return;
    }
    signal(pid, false);
    if !wait_for_exit(pid) && pid_alive(pid) {
        signal(pid, true);
        wait_for_exit(pid);
    }
}

/// Ask `pid` to stop, forcefully when `hard`. The two platforms are structurally parallel: a
/// graceful request first, an unconditional kill on escalation.
fn signal(pid: u32, hard: bool) {
    #[cfg(unix)]
    unsafe {
        libc::kill(
            pid as libc::pid_t,
            if hard { libc::SIGKILL } else { libc::SIGTERM },
        );
    }
    #[cfg(windows)]
    {
        let mut command = Command::new("taskkill");
        if hard {
            command.arg("/F");
        }
        let _ = command
            .args(["/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Wait up to two seconds for `pid` to be gone; `true` once it is. The replacement binds the same
/// address, so this is a precondition of starting the new workload, not politeness.
fn wait_for_exit(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Stop the workload a scenario's fixture is managing. The agent cannot do this — the workload is
/// deliberately outside every tree it owns — so the scenario that started one ends it. The recorded
/// pid may name a workload that already exited on its own (the normal case for the fault modes), so
/// [`stop_pid`] observes liveness before it signals; a real reconciler hook must do the same, where
/// the victim of a stale pid would be a production process.
fn stop_workload(dir: &Path) {
    let root = root(dir);
    if let Some(workload) = read_workload(&root) {
        stop_pid(workload.pid);
    }
    let _ = std::fs::remove_file(record_path(&root));
}

/// Ends the fixture's workload when the scenario's scope ends. The workload is deliberately outside
/// every tree the node stack owns, so the scenario that started one is the only thing that can end
/// it — and a failing scenario returns early, so ending it must not be a statement the author has to
/// remember to write.
///
/// Bind it before the `Proc`/`Service` handles: Rust drops in reverse declaration order, so the
/// guard declared first is dropped last, which is the ordering a correct manual teardown writes.
pub struct Workload(PathBuf);

pub fn workload(dir: &Path) -> Workload {
    Workload(dir.to_path_buf())
}

impl Workload {
    /// End the workload before the scope does, for a scenario that observes the address being
    /// released. Consumes the guard, so `Drop` remains the one mechanism.
    pub fn stop(self) {}
}

impl Drop for Workload {
    fn drop(&mut self) {
        stop_workload(&self.0);
    }
}

/// The PID of the workload the fixture under `dir` currently manages.
pub fn workload_pid(dir: &Path) -> Option<u32> {
    read_workload(&root(dir)).map(|workload| workload.pid)
}

// ---------------------------- migration-shaped adapter ----------------------------

/// A stand-in for a stateful application whose upgrade runs a one-way content migration. Each
/// operation verifies the durable prerequisite the preceding one produced, so running operations
/// out of order is a hard failure rather than another marker in a directory.
fn migrate(root: &Path, mode: Migration, operation: Operation, id: &str, version: &str) -> R {
    let state = root.join("migration-state");
    let live = state.join("live");
    // The restore point is keyed by the attempt that TOOK it, and which attempt that was is durable
    // sub-progress this hook keeps for itself — exactly what the protocol reserves `--state-dir`
    // for. The compensating direction carries its own attempt id (a transaction never reuses one id
    // with different arguments), so `rollback` looks the restore point up rather than assuming its
    // own id named it.
    let restore_point = state.join("restore-point");
    let backup = |taken_by: &str| state.join("backups").join(taken_by);
    std::fs::create_dir_all(&state).map_err(str_err)?;
    // A real stateful upgrade spends meaningful time in backup, quiescence, startup, and migration.
    // The fixed cost keeps CI deterministic while giving the operations observable, non-instant
    // duration, so the agent's ordering and hook-timeout behaviour is exercised rather than raced
    // past.
    std::thread::sleep(Duration::from_millis(250));
    match operation {
        Operation::Healthcheck => Ok(()),
        Operation::Apply => {
            if version == "1.0.0" {
                return Ok(());
            }
            // A one-way migration is exactly the operation the execution contract's
            // at-least-once rule is hardest on: a crash between the migrating write and the
            // checkpoint replays this invocation over already-migrated content. So the migrating
            // half is skipped when its result is already on disk — the baseline check, which would
            // now fail, is a check on *whether the migration still has to run*, and it deliberately
            // sits in front of the backup copy so a replay can never overwrite the restore point.
            if std::fs::read_to_string(state.join("migration-finalized"))
                .is_ok_and(|finalized| finalized == id)
            {
                return Ok(());
            }
            let migrated = std::fs::read_to_string(live.join("content.db")).map_err(str_err)?
                == format!("migrated-{version}\n")
                && std::fs::read_to_string(live.join("app.war")).map_err(str_err)?
                    == format!("{version}\n");
            if !migrated {
                if std::fs::read_to_string(live.join("content.db")).map_err(str_err)?
                    != "baseline-content\n"
                    || std::fs::read_to_string(live.join("app.war")).map_err(str_err)? != "1.0.0\n"
                {
                    return fail("the migration-shaped apply found an invalid baseline");
                }
                let backup = backup(id);
                std::fs::create_dir_all(&backup).map_err(str_err)?;
                std::fs::copy(live.join("content.db"), backup.join("content.db"))
                    .map_err(str_err)?;
                std::fs::copy(live.join("app.war"), backup.join("app.war")).map_err(str_err)?;
                // Recorded before the one-way write, so a crash between them still leaves the
                // compensating direction able to find what it must restore.
                std::fs::write(&restore_point, id.as_bytes()).map_err(str_err)?;
                std::fs::write(live.join("app.war"), format!("{version}\n")).map_err(str_err)?;
                std::fs::write(live.join("content.db"), format!("migrated-{version}\n"))
                    .map_err(str_err)?;
            }
            if mode == Migration::FailApply {
                return fail("injected migration failure");
            }
            std::fs::write(state.join("migration-finalized"), id.as_bytes()).map_err(str_err)
        }
        Operation::Rollback => {
            let taken_by = std::fs::read_to_string(&restore_point).map_err(str_err)?;
            let backup = backup(taken_by.trim());
            std::fs::copy(backup.join("content.db"), live.join("content.db")).map_err(str_err)?;
            std::fs::copy(backup.join("app.war"), live.join("app.war")).map_err(str_err)?;
            std::fs::write(state.join("rollback-completed"), id.as_bytes()).map_err(str_err)
        }
        Operation::Inspect => Ok(()),
    }
}

/// The migration-shaped healthcheck gate: the ordinary 1.0.0 predecessor has no migration state to
/// inspect, while every check after the migrating apply requires the receipt that apply produced.
fn migration_gate(root: &Path, version: &str) -> R {
    if version == "1.0.0" || root.join("migration-state/migration-finalized").is_file() {
        return Ok(());
    }
    fail("the healthcheck ran before the migration was finalized")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mode_composes_a_workload_with_an_injected_failure() {
        let mode = Mode::parse("workload=127.0.0.1:1234,fault=unhealthy,fail=apply").unwrap();
        assert_eq!(mode.workload.as_deref(), Some("127.0.0.1:1234"));
        assert_eq!(mode.fault.as_deref(), Some("unhealthy"));
        assert!(mode.fails(Operation::Apply, FORWARD_CANDIDATE));
        // The forward injection must not fire on the rollback that restores the predecessor.
        assert!(!mode.fails(Operation::Apply, "1.0.0"));
        assert!(!mode.fails(Operation::Rollback, "1.0.0"));
    }

    #[test]
    fn a_rollback_failure_is_unconditional() {
        let mode = Mode::parse("fail=apply,fail=rollback").unwrap();
        assert!(mode.fails(Operation::Rollback, "1.0.0"));
    }

    #[test]
    fn the_default_mode_only_records() {
        let mode = Mode::parse("inert").unwrap();
        assert!(mode.workload.is_none() && mode.fail.is_empty() && mode.hang.is_none());
        assert!(!mode.migration.gates_health());
    }

    #[test]
    fn an_unknown_directive_is_refused_rather_than_silently_ignored() {
        assert!(Mode::parse("workload=127.0.0.1:1,drain-hold=5s").is_err());
    }

    /// The double-execution window, at unit scope: a crash between the migrating write and the
    /// agent's checkpoint replays `apply` under the SAME attempt id. The replay must succeed
    /// without touching the backup — a reference reconciler that rejected its own migrated state
    /// would earn the candidate a spurious rejection in exactly the window the execution contract
    /// exists for.
    #[test]
    fn a_replayed_migrating_apply_succeeds_without_disturbing_its_backup() {
        let root =
            std::env::temp_dir().join(format!("e2e-migration-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let live = root.join("migration-state/live");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("content.db"), b"baseline-content\n").unwrap();
        std::fs::write(live.join("app.war"), b"1.0.0\n").unwrap();

        let id = "attempt";
        migrate(&root, Migration::On, Operation::Apply, id, "2.0.0").unwrap();
        migrate(&root, Migration::On, Operation::Apply, id, "2.0.0")
            .expect("a replayed apply converges rather than rejecting its own result");

        let backup = root.join("migration-state/backups").join(id);
        assert_eq!(
            std::fs::read_to_string(backup.join("content.db")).unwrap(),
            "baseline-content\n",
            "the replay overwrote the restore point with migrated content"
        );
        assert_eq!(
            std::fs::read_to_string(live.join("content.db")).unwrap(),
            "migrated-2.0.0\n"
        );
        // And the rollback that a later failure would run still restores the true baseline.
        migrate(&root, Migration::On, Operation::Rollback, id, "1.0.0").unwrap();
        assert_eq!(
            std::fs::read_to_string(live.join("content.db")).unwrap(),
            "baseline-content\n"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_fixture_dispatch_marker_cannot_be_missed_by_a_driver() {
        assert!(is_invocation(["apply", "--protocol", "1", "--", FLAG]));
        assert!(!is_invocation(["killfuzz"]));
    }
}
