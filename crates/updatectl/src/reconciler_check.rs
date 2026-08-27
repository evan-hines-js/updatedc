//! `updatectl reconciler-check` — the conformance harness a reconciler author runs before
//! publishing.
//!
//! The agent can enforce ordering, bounds, identity, and result handling, but it cannot prove that
//! a reconciler is idempotent, read-only where it must be, or stable across replays
//! (`docs/node-reconciler-protocol.md`). Those are exactly the properties whose violation shows up
//! as a rare, crash-timing-dependent production failure — a replayed `apply` that fails the second
//! time, an `inspect` that mutates the state directory, a fingerprint that changes on every probe
//! and re-arms the fleet's drift detection forever.
//!
//! So this exercises them directly: it builds a scratch install root and state directory — from
//! [`Paths`](updated::config::Paths), the agent's own layout — invokes the hook through the *same*
//! argv builder ([`Arguments`](updated_contracts::reconciler::Arguments)) and the *same* invocation
//! environment ([`apply_environment`](updated::reconciler::apply_environment)) the agent invokes
//! through, with a null stdin, and replays every operation the way crash recovery does, under the
//! same attempt id.
//!
//! It also invokes it the way the agent's own invoker runs it, and not merely with the agent's
//! argv: a contained process tree with parent-death containment, torn down on every exit path,
//! under a deadline. That is not fidelity for its own sake. Detaching the workload is a hook
//! obligation the protocol states and nothing else can check — a harness with no tree to tear down
//! passes a hook that forgot, which then loses its workload to its own first successful `apply`
//! (see [`Harness::invoke`]).
//!
//! It is deliberately not a test framework: one linear run, one human-readable line per check, and
//! a non-zero exit if any check fails.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use clap::Args;
use updated_contracts::dataflow::FileSnapshot;
#[cfg(test)]
use updated_contracts::reconciler::FLAGS;
use updated_contracts::reconciler::{Arguments, Operation, Reason};

use crate::Error;

/// The transaction token both directions of the checked transaction are keyed to. The compensating
/// direction is the agent's own derivation (`Transaction::rollback_attempt_id`): the forward token
/// with `r` appended.
const TRANSACTION_ATTEMPT: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The versions the scratch releases carry. Two different ones, so a hook that reads
/// `--candidate-version` and `--predecessor-version` cannot pass by accident.
const CANDIDATE_VERSION: &str = "2.0.0";
const PREDECESSOR_VERSION: &str = "1.0.0";

/// How long one invocation may run before its tree is killed and the check fails. A conformance run
/// has no deployment to read `lifecycle.timeout_millis` from, so this stands in for the agent's
/// `agent::update::lifecycle_timeout`: generous for a real `apply`, and finite, which is the whole
/// point — a hook that never exits must fail the author's run rather than wedge their terminal.
const INVOCATION_TIMEOUT: Duration = Duration::from_secs(120);

/// How often the wait loop looks for the hook's exit — the agent's own polling cadence.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long the captured pipes are given to reach EOF once the hook itself has exited.
///
/// The hook is gone, so its own descriptors are closed; in a conforming run EOF has already
/// happened and this waits for nothing. A pipe still open past it means a descendant outlived the
/// hook while holding the inherited stdout/stderr — the process left inside the tree that
/// [`Invocation::left_tree`] reports, and the thing a plain `Command::output()` would have waited
/// on forever.
const TREE_GRACE: Duration = Duration::from_millis(500);

#[derive(Args, Debug)]
pub(crate) struct ReconcilerCheckArgs {
    /// The reconciler executable to check — the release's own entrypoint, exactly as the signed
    /// bundle carries it.
    hook: PathBuf,

    /// Build the scratch install root here instead of in a temporary directory, and leave it in
    /// place afterwards. Without it a run that fails keeps its scratch tree and prints the path,
    /// and a run that passes cleans up.
    #[arg(long)]
    scratch: Option<PathBuf>,

    /// Publisher arguments, passed after `--` exactly as a deployment's configured `args` are.
    #[arg(last = true)]
    publisher_args: Vec<String>,
}

/// Where the scratch machine is built: an operator-named directory that outlives the run, or a
/// temporary one that survives only a failure — which is the only time its contents are evidence.
enum Scratch {
    Named(PathBuf),
    Temporary(tempfile::TempDir),
}

impl Scratch {
    fn path(&self) -> &Path {
        match self {
            Self::Named(path) => path,
            Self::Temporary(directory) => directory.path(),
        }
    }

    /// Give up ownership so the tree can be inspected, and report where it is.
    fn keep(self) -> PathBuf {
        match self {
            Self::Named(path) => path,
            Self::Temporary(directory) => directory.keep(),
        }
    }
}

/// One release as the protocol names it: the directory to converge onto or away from, and its
/// version.
struct Release {
    dir: PathBuf,
    version: &'static str,
}

/// The scratch machine one conformance run is performed against.
///
/// The directory *names* below are not part of the contract — a reconciler is handed absolute paths
/// and may not assume anything about their shape — but the *set* of them is: every path the agent
/// passes exists before the first invocation. Input and output directories are private and fresh
/// for every invocation, exactly as they are on the agent.
struct Harness {
    hook: PathBuf,
    cwd: PathBuf,
    install_root: PathBuf,
    state_dir: PathBuf,
    candidate: Release,
    predecessor: Release,
    publisher_args: Vec<String>,
}

/// What one invocation did: enough to name it in a failure and to compare it against its replay.
struct Invocation {
    argv: String,
    /// The exit status as the agent reads it — `Some(code)`, `None` for death by signal, and
    /// `None` with [`timed_out`](Self::timed_out) for a hook the deadline killed.
    code: Option<i32>,
    /// The deadline expired and the tree was killed. A hook that hangs must fail the run rather
    /// than hang the author's terminal.
    timed_out: bool,
    /// Something inside the hook's process tree outlived the hook itself, still holding the
    /// captured stdout/stderr. See [`Harness::invoke`].
    left_tree: bool,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: String,
    outputs: Result<FileSnapshot, String>,
    result: Result<Option<updated_contracts::reconciler::MutationResolution>, String>,
}

impl Invocation {
    fn succeeded(&self) -> bool {
        self.code == Some(0)
    }

    fn mutation_succeeded(&self) -> bool {
        self.succeeded()
            && matches!(
                &self.result,
                Ok(Some(
                    updated_contracts::reconciler::MutationResolution::Succeeded(_)
                ))
            )
    }

    fn published_no_result(&self) -> bool {
        matches!(self.result, Ok(None))
    }

    fn reports_changed(&self, expected: bool) -> bool {
        matches!(
            &self.result,
            Ok(Some(updated_contracts::reconciler::MutationResolution::Succeeded(result)))
                if result.changed() == expected
        )
    }

    /// How the invocation ended, for the report line.
    fn status(&self) -> String {
        match self.code {
            Some(code) => format!("exit {code}"),
            None if self.timed_out => format!(
                "no exit within the {}s conformance deadline; the tree was killed",
                INVOCATION_TIMEOUT.as_secs()
            ),
            None => "killed by a signal".to_string(),
        }
    }

    fn result_diagnostic(&self) -> String {
        match &self.result {
            Ok(Some(updated_contracts::reconciler::MutationResolution::Succeeded(result))) => {
                format!(
                    "; result status=succeeded, changed={}, hostAction={:?}",
                    result.changed(),
                    result.host_action()
                )
            }
            Ok(Some(updated_contracts::reconciler::MutationResolution::Retry(result))) => format!(
                "; result status=retry, retryAfterSeconds={}",
                result.after_seconds()
            ),
            Ok(None) => "; no result document was published".to_string(),
            Err(error) => format!("; invalid result document: {error}"),
        }
    }

    /// The hook's own explanation, trimmed to one line so a chatty reconciler cannot bury the
    /// report.
    fn diagnostic(&self) -> String {
        match self.stderr.lines().find(|line| !line.trim().is_empty()) {
            Some(line) => format!("; stderr: {line}"),
            None => String::new(),
        }
    }
}

impl Harness {
    fn new(root: &Path, hook: PathBuf, publisher_args: Vec<String>) -> io::Result<Self> {
        let install_root = root.join("install-root");
        // The agent's own layout, from the one definition of it rather than from paths respelled
        // here: a harness that certified hooks against directories no node uses is exactly the
        // drift `Paths` exists to prevent. (The enrollment-state root is unused by the two
        // directories this harness needs; a conformance run has no enrollment.)
        let paths = updated::config::Paths::resolve(&install_root, &install_root);
        let state_dir = paths.reconciler_state_dir("conformance");
        let candidate = paths
            .versions
            .join(format!("{CANDIDATE_VERSION}-candidate"));
        let predecessor = paths
            .versions
            .join(format!("{PREDECESSOR_VERSION}-predecessor"));
        for directory in [&state_dir, &candidate, &predecessor] {
            std::fs::create_dir_all(directory)?;
        }
        Ok(Harness {
            cwd: hook
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf(),
            hook,
            install_root,
            state_dir,
            candidate: Release {
                dir: candidate,
                version: CANDIDATE_VERSION,
            },
            predecessor: Release {
                dir: predecessor,
                version: PREDECESSOR_VERSION,
            },
            publisher_args,
        })
    }

    /// Invoke the hook the way the agent's own invoker does: the argv from
    /// `agent::update::prepare_lifecycle_command`, run as
    /// `agent::update::run_prepared_lifecycle_command_blocking` runs it — a contained tree with
    /// parent-death containment, torn down with `kill_tree` on EVERY exit path, under a deadline.
    ///
    /// `converge_onto` is always `--candidate` — in both directions, per the protocol: a rollback
    /// passes the release being restored as the candidate and the failed one as the predecessor.
    /// The argv comes from the published grammar's own builder, the one the agent invokes through,
    /// so this harness cannot check a hook against a flag the agent does not send or against a
    /// value the agent would put behind a different flag.
    ///
    /// The containment is not decoration: it is the only way this harness can observe two failures
    /// that otherwise appear for the first time on a real node.
    ///
    /// 1. `docs/node-reconciler-protocol.md` makes detaching a hook obligation — "a workload
    ///    started inside the tree is killed by its own successful `apply`". A harness that never
    ///    tears the tree down passes a hook that forgot to `setsid`, which then loses its workload
    ///    to the first real `apply`. Here the tree is torn down, and a descendant still holding the
    ///    captured pipes a moment after the hook returned is reported as
    ///    [`left_tree`](Invocation::left_tree).
    /// 2. Reading the pipes to EOF with no deadline is the hazard the agent comments on directly:
    ///    a hook that detaches with `setsid` alone keeps the inherited stdout/stderr open, so a
    ///    plain `Command::output()` waits on it forever with nothing to break the wait. The
    ///    deadline plus the teardown is what bounds it.
    fn invoke(
        &self,
        operation: Operation,
        protocol: &str,
        attempt_id: &str,
        reason: Reason,
        converge_onto: &Release,
        undoing: &Release,
    ) -> io::Result<Invocation> {
        operation
            .validate_invocation(reason, attempt_id)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.invoke_raw(
            operation.as_str(),
            protocol,
            attempt_id,
            reason,
            converge_onto,
            undoing,
        )
    }

    /// Bypass the typed operation gate only for conformance checks that intentionally send an
    /// unknown wire operation. Every invocation the agent can actually emit goes through
    /// [`Self::invoke`] and therefore the contracts crate's canonical invocation grammar.
    fn invoke_raw(
        &self,
        operation: &str,
        protocol: &str,
        attempt_id: &str,
        reason: Reason,
        converge_onto: &Release,
        undoing: &Release,
    ) -> io::Result<Invocation> {
        let exchange = tempfile::Builder::new()
            .prefix("reconciler-invocation-")
            .tempdir_in(&self.state_dir)?;
        let input_dir = exchange.path().join("inputs");
        let output_dir = exchange.path().join("outputs");
        let result_file = exchange.path().join("result.json");
        // Mirror the agent's one file-exchange invariant. Hooks may publish credentials here, so
        // the conformance path must not create a weaker directory than production does.
        foundation::durable::create_private_directory(&input_dir)?;
        foundation::durable::create_private_directory(&output_dir)?;
        let arguments = Arguments {
            protocol: OsStr::new(protocol),
            attempt_id: OsStr::new(attempt_id),
            reason,
            install_root: self.install_root.as_os_str(),
            state_dir: self.state_dir.as_os_str(),
            candidate: converge_onto.dir.as_os_str(),
            candidate_version: OsStr::new(converge_onto.version),
            output_dir: output_dir.as_os_str(),
            result_file: result_file.as_os_str(),
            input_dir: input_dir.as_os_str(),
            predecessor: undoing.dir.as_os_str(),
            predecessor_version: OsStr::new(undoing.version),
        };
        let mut command = Command::new(&self.hook);
        command.arg(operation);
        let mut argv = vec![self.hook.display().to_string(), operation.to_string()];
        for (flag, value) in arguments.argv() {
            command.arg(flag).arg(value);
            argv.push(flag.to_string());
            argv.push(value.to_string_lossy().into_owned());
        }
        if !self.publisher_args.is_empty() {
            command.arg("--").args(&self.publisher_args);
            argv.push("--".to_string());
            argv.extend(self.publisher_args.iter().cloned());
        }
        command
            .current_dir(&self.cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // THE invocation environment, from the agent's own chokepoint: cleared, plus the minimal
        // search path a script needs to find an interpreter. Spelling `env_clear()` here instead
        // made this harness STRICTER than every real node — no `PATH` on Unix (survivable only
        // because `/bin/sh` substitutes one, so a hook execing by name from Python or Go failed
        // conformance and passed in production) and no `SystemRoot` on Windows, where nothing that
        // needs PowerShell or cmd can start at all. Application data is available only through the
        // input directory, which is empty here because a conformance run has no control plane.
        updated::reconciler::apply_environment(&mut command);
        foundation::process::arrange_parent_death_signal(&mut command);
        let mut child = foundation::process::ContainedChild::spawn(command)?;
        let stdout = updated::reconciler::capture_output(
            child
                .take_stdout()
                .ok_or_else(|| io::Error::other("the hook's stdout was not captured"))?,
        );
        let stderr = updated::reconciler::capture_output(
            child
                .take_stderr()
                .ok_or_else(|| io::Error::other("the hook's stderr was not captured"))?,
        );
        let deadline = Instant::now() + INVOCATION_TIMEOUT;
        let exited = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(POLL_INTERVAL);
        };
        // Read BEFORE the teardown, or the teardown is what closed the pipes and the evidence is
        // gone: an open pipe once the root has exited means a descendant is still holding it, so
        // the hook left something inside the tree the agent is about to kill.
        type CollectedOutput = (
            Option<io::Result<(Vec<u8>, bool)>>,
            Option<io::Result<(Vec<u8>, bool)>>,
        );
        let mut collected: CollectedOutput = (None, None);
        let left_tree = if exited.is_some() {
            collected = (
                stdout.recv_timeout(TREE_GRACE).ok(),
                stderr.recv_timeout(TREE_GRACE).ok(),
            );
            collected.0.is_none() || collected.1.is_none()
        } else {
            false
        };
        // On every exit path, exactly as the agent does — success included.
        child.kill_tree()?;
        if exited.is_none() {
            let _ = child.wait();
        }
        // Whatever the readers still had; the teardown released them. Still bounded, because a
        // descendant that escaped the tree entirely holds the pipe open past the kill — waiting on
        // it unbounded here would reintroduce the exact hang the deadline above exists to end.
        let (stdout, stdout_truncated) = collected
            .0
            .or_else(|| stdout.recv_timeout(TREE_GRACE).ok())
            .unwrap_or_else(|| Ok((Vec::new(), true)))?;
        let (stderr, _) = collected
            .1
            .or_else(|| stderr.recv_timeout(TREE_GRACE).ok())
            .unwrap_or_else(|| Ok((Vec::new(), true)))?;
        let result = operation
            .parse::<Operation>()
            .map_or(Ok(None), |operation| {
                updated::reconciler::take_result(&result_file, operation)
                    .map(|result| match result {
                        updated::reconciler::InvocationResult::Mutation(document) => Some(document),
                        updated::reconciler::InvocationResult::Observation => None,
                    })
                    .map_err(|error| error.to_string())
            });
        let outputs =
            updated::reconciler::snapshot_directory(&output_dir).map_err(|error| error.to_string());
        Ok(Invocation {
            argv: argv.join(" "),
            code: exited.and_then(|status| status.code()),
            timed_out: exited.is_none(),
            left_tree,
            stdout,
            stdout_truncated,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            outputs,
            result,
        })
    }
}

/// A digest over the whole state-directory tree: every path, its kind, and every file's contents.
///
/// This is what makes "an observation must not mutate" checkable. Names are included as well as
/// contents, so a hook that deletes one scratch file and writes another of the same size is still
/// caught.
fn tree_digest(root: &Path) -> io::Result<String> {
    fn walk(
        root: &Path,
        at: &Path,
        digest: &mut updated_contracts::digest::Sha256Hasher,
    ) -> io::Result<()> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(at)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<_>>()?;
        // Directory order is not defined; the digest must be.
        entries.sort();
        for entry in entries {
            let relative = entry.strip_prefix(root).unwrap_or(&entry);
            digest.update(relative.as_os_str().as_encoded_bytes());
            digest.update(&[0]);
            let kind = std::fs::symlink_metadata(&entry)?.file_type();
            if kind.is_dir() {
                digest.update(b"dir\0");
                walk(root, &entry, digest)?;
            } else if kind.is_file() {
                digest.update(b"file\0");
                digest_regular_file(root, &entry, digest)?;
            } else {
                digest.update(b"other\0");
            }
            digest.update(&[0]);
        }
        Ok(())
    }
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    walk(root, root, &mut digest)?;
    Ok(digest.finish_hex())
}

/// Hash one file from the same regular, no-follow handle that proved its final path component.
///
/// `walk` inspects directory-entry kinds to decide whether to recurse, but that observation cannot
/// authorize a later plain open: a hook can replace a regular file with a symlink between those
/// operations. The shared opener closes that final-component race on every supported platform.
fn digest_regular_file(
    root: &Path,
    path: &Path,
    digest: &mut updated_contracts::digest::Sha256Hasher,
) -> io::Result<()> {
    use io::Read as _;

    let mut file =
        foundation::file::open_regular_beneath(root, path, foundation::file::FinalSymlink::Refuse)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(())
}

/// The running verdict: one line per check, and the count that decides the exit status.
struct Report {
    checks: usize,
    failures: usize,
}

impl Report {
    fn check(&mut self, name: &str, passed: bool, evidence: String) {
        self.checks += 1;
        if passed {
            println!("PASS  {name}\n        {evidence}");
        } else {
            self.failures += 1;
            println!("FAIL  {name}\n        {evidence}");
        }
    }
}

pub(crate) fn reconciler_check(args: ReconcilerCheckArgs) -> Result<(), Error> {
    let hook = std::fs::canonicalize(&args.hook)
        .map_err(|error| format!("{}: {error}", args.hook.display()))?;
    let scratch = match args.scratch {
        Some(path) => {
            std::fs::create_dir_all(&path)?;
            Scratch::Named(path)
        }
        None => Scratch::Temporary(tempfile::tempdir()?),
    };
    let harness = Harness::new(scratch.path(), hook, args.publisher_args)?;
    println!(
        "checking {} against node reconciler protocol {}\n  install root: {}\n  state dir:    {}\n",
        harness.hook.display(),
        updated_contracts::reconciler::PROTOCOL,
        harness.install_root.display(),
        harness.state_dir.display()
    );
    let mut report = Report {
        checks: 0,
        failures: 0,
    };

    // At-least-once: the agent journals its intent before invoking, so after a crash it cannot know
    // whether an invocation half-ran and its only correct recovery is to invoke again — with the
    // same attempt id and the same arguments.
    let first = harness.invoke(
        Operation::Apply,
        updated_contracts::reconciler::PROTOCOL,
        TRANSACTION_ATTEMPT,
        Reason::Update,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "apply/update succeeds",
        first.mutation_succeeded(),
        format!(
            "{}{}\n        {}",
            first.status(),
            first.diagnostic(),
            first.argv
        ),
    );
    // The obligation `docs/node-reconciler-protocol.md` puts on the hook and nothing else could
    // check: the agent kills the invocation's process tree on EVERY apply, success included, so a
    // workload started inside it is killed by its own successful apply. A hook that forgot to
    // detach shows up here — and only here — instead of on the first real node.
    report.check(
        "apply leaves nothing inside the invocation's process tree",
        !first.left_tree,
        if first.left_tree {
            format!(
                "something apply started was still holding the invocation's stdout/stderr {}ms \
                 after it exited, so it is still inside the tree the agent kills on every apply — \
                 the workload would not survive its own deployment. Detach it (`setsid`, or \
                 `CREATE_BREAKAWAY_FROM_JOB`) AND redirect its stdio off the inherited pipes; \
                 detaching alone still holds them.",
                TREE_GRACE.as_millis()
            )
        } else {
            "both captured pipes reached EOF as soon as apply returned".to_string()
        },
    );
    let first_outputs = first.outputs.clone();
    let replay = harness.invoke(
        Operation::Apply,
        updated_contracts::reconciler::PROTOCOL,
        TRANSACTION_ATTEMPT,
        Reason::Update,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "apply is replay-tolerant (same attempt id, run twice)",
        replay.mutation_succeeded() && replay.reports_changed(false),
        format!(
            "first {}, replay {}{}{}",
            first.status(),
            replay.status(),
            replay.diagnostic(),
            replay.result_diagnostic()
        ),
    );
    let replayed_outputs = replay.outputs.clone();
    report.check(
        "output directory contains only published, bounded files",
        first_outputs.is_ok() && replayed_outputs.is_ok(),
        match (&first_outputs, &replayed_outputs) {
            (Ok(before), Ok(after)) => format!(
                "{} files on the first invocation, {} on replay",
                before.files.len(),
                after.files.len()
            ),
            (Err(error), _) => format!("first invocation rejected: {error}"),
            (_, Err(error)) => format!("replay rejected: {error}"),
        },
    );
    report.check(
        "outputs are identical across a replay with fresh directories",
        matches!((&first_outputs, &replayed_outputs), (Ok(before), Ok(after)) if before == after),
        match (&first_outputs, &replayed_outputs) {
            (Ok(before), Ok(after)) if before == after => {
                format!("{} files, unchanged", before.files.len())
            }
            (Ok(before), Ok(after)) => format!(
                "first invocation produced {:?}, replay produced {:?}",
                before.files.keys().collect::<Vec<_>>(),
                after.files.keys().collect::<Vec<_>>()
            ),
            _ => "one invocation produced an invalid output directory".to_string(),
        },
    );

    // Observations. The agent repeats these freely and may have both in flight at once, so each
    // must answer consistently and neither may write.
    let before = tree_digest(&harness.state_dir)?;
    let health: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Healthcheck,
                updated_contracts::reconciler::PROTOCOL,
                updated_contracts::reconciler::attempt::PERIODIC,
                Reason::Restart,
                &harness.candidate,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "healthcheck answers consistently across a repeated probe",
        health[0].code == health[1].code && health.iter().all(Invocation::published_no_result),
        format!(
            "{} then {}{}{}",
            health[0].status(),
            health[1].status(),
            health[1].diagnostic(),
            health[1].result_diagnostic()
        ),
    );
    let inspect: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Inspect,
                updated_contracts::reconciler::PROTOCOL,
                updated_contracts::reconciler::attempt::FINGERPRINT,
                Reason::Restart,
                &harness.candidate,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "inspect answers consistently across a repeated probe",
        inspect[0].code == inspect[1].code && inspect.iter().all(Invocation::published_no_result),
        format!(
            "{} then {}{}{}",
            inspect[0].status(),
            inspect[1].status(),
            inspect[1].diagnostic(),
            inspect[1].result_diagnostic()
        ),
    );
    // Non-empty stdout is the fingerprint material; a fingerprint that changes while nothing has
    // changed re-arms the fleet's drift detection on every probe.
    report.check(
        "inspect writes stable, non-empty fingerprint material to stdout",
        !inspect[0].stdout_truncated
            && !inspect[1].stdout_truncated
            && !inspect[0].stdout.is_empty()
            && inspect[0].stdout == inspect[1].stdout,
        if inspect[0].stdout_truncated || inspect[1].stdout_truncated {
            format!(
                "stdout exceeded the {}-byte limit; the agent would refuse to attest it",
                updated::reconciler::OUTPUT_LIMIT
            )
        } else if inspect[0].stdout.is_empty() {
            "stdout was empty; the agent publishes no fingerprint for this node".to_string()
        } else if inspect[0].stdout == inspect[1].stdout {
            format!(
                "{} bytes, identical across the pair",
                inspect[0].stdout.len()
            )
        } else {
            format!(
                "{} bytes then {} bytes, differing: {:?} vs {:?}",
                inspect[0].stdout.len(),
                inspect[1].stdout.len(),
                String::from_utf8_lossy(&inspect[0].stdout),
                String::from_utf8_lossy(&inspect[1].stdout)
            )
        },
    );
    let after = tree_digest(&harness.state_dir)?;
    report.check(
        "healthcheck and inspect leave the state directory untouched",
        before == after,
        if before == after {
            format!("state-dir digest {before} unchanged by four observations")
        } else {
            format!("state-dir digest {before} became {after}: an observation with side effects turns every probe into a mutation replay")
        },
    );

    // Compensation. The rollback direction carries its own token — the forward one with `r`
    // appended — and converges ONTO the release being restored, so candidate and predecessor swap.
    let rollback_attempt = format!("{TRANSACTION_ATTEMPT}r");
    let rollback: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Rollback,
                updated_contracts::reconciler::PROTOCOL,
                &rollback_attempt,
                Reason::Update,
                &harness.predecessor,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "rollback is replay-tolerant (compensating attempt id, run twice)",
        rollback.iter().all(Invocation::mutation_succeeded) && rollback[1].reports_changed(false),
        format!(
            "--attempt-id {rollback_attempt}, --candidate {} (restored), --predecessor {} \
             (failed): {} then {}{}{}",
            harness.predecessor.version,
            harness.candidate.version,
            rollback[0].status(),
            rollback[1].status(),
            rollback[1].diagnostic(),
            rollback[1].result_diagnostic()
        ),
    );
    report.check(
        "rollback outputs are valid and identical across a fresh-directory replay",
        matches!(
            (&rollback[0].outputs, &rollback[1].outputs),
            (Ok(before), Ok(after)) if before == after
        ),
        match (&rollback[0].outputs, &rollback[1].outputs) {
            (Ok(before), Ok(after)) if before == after => {
                format!("{} files, unchanged", before.files.len())
            }
            (Ok(before), Ok(after)) => format!(
                "first invocation produced {:?}, replay produced {:?}",
                before.files.keys().collect::<Vec<_>>(),
                after.files.keys().collect::<Vec<_>>()
            ),
            (Err(error), _) => format!("first invocation rejected: {error}"),
            (_, Err(error)) => format!("replay rejected: {error}"),
        },
    );

    // The two refusals. A hook that runs whatever it is handed is a hook that will one day converge
    // a machine on a protocol it does not implement.
    let unknown = harness.invoke_raw(
        "converge",
        updated_contracts::reconciler::PROTOCOL,
        TRANSACTION_ATTEMPT,
        Reason::Update,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "an unknown operation is refused",
        !unknown.succeeded(),
        format!("`converge` ended with {}", unknown.status()),
    );
    let wrong_protocol = harness.invoke(
        Operation::Apply,
        "2",
        TRANSACTION_ATTEMPT,
        Reason::Update,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "a protocol version this hook does not implement is refused",
        !wrong_protocol.succeeded(),
        format!("`--protocol 2` ended with {}", wrong_protocol.status()),
    );

    println!("\n{} checks, {} failed", report.checks, report.failures);
    if report.failures > 0 {
        // The scratch tree is what the author needs to see when something failed, so it outlives
        // the run whenever there is something to look at.
        println!("scratch install root kept at {}", scratch.keep().display());
        return Err(format!(
            "{} of {} conformance checks failed",
            report.failures, report.checks
        )
        .into());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The body of a reconciler that answers the whole protocol correctly: it parses the published
    /// grammar, refuses an unknown operation and an unimplemented protocol, keys its work to the
    /// attempt id so a replay is a no-op, and observes without writing.
    const CONFORMANT: &str = r#"#!/bin/sh
set -eu
operation=$1; shift
protocol= reason= attempt= state_dir= output_dir= result_file=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --attempt-id) attempt=$2; shift 2 ;;
    --reason) reason=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --output-dir) output_dir=$2; shift 2 ;;
    --result-file) result_file=$2; shift 2 ;;
    --install-root|--candidate|--candidate-version|--input-dir|--predecessor|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$protocol" = 1 ] || exit 2
case "$operation" in
  apply|rollback)
    # Keyed to the attempt, never to invocation count: the replay finds its marker and stops.
    marker="$state_dir/$operation.$attempt.done"
    changed=false
    if [ ! -f "$marker" ]; then
      : >"$marker"
      changed=true
    fi
    # Every invocation receives a fresh output directory, including a replay of the same attempt.
    # Re-emitting the same declaration is observation, not a repeated side effect.
    printf 'https://svc:8200' >"$output_dir/endpoint"
    printf '{"schema":1,"status":"succeeded","changed":%s,"hostAction":"none","message":null}' "$changed" >"$result_file"
    ;;
  healthcheck) ;;
  inspect) printf 'state=ready\n' ;;
  *) echo "unknown operation: $operation" >&2; exit 2 ;;
esac
"#;

    /// The same reconciler with one defect: `apply` refuses to run twice, which is precisely what
    /// crash recovery does to it.
    const BREAKS_IDEMPOTENCE: &str = r#"#!/bin/sh
set -eu
operation=$1; shift
protocol= state_dir= result_file=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --result-file) result_file=$2; shift 2 ;;
    --attempt-id|--reason|--install-root|--candidate|--candidate-version|--output-dir|--input-dir|--predecessor|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$protocol" = 1 ] || exit 2
case "$operation" in
  apply|rollback)
    if [ -f "$state_dir/$operation.installed" ]; then
      echo "$operation has already run" >&2
      exit 1
    fi
    : >"$state_dir/$operation.installed"
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$result_file"
    ;;
  healthcheck) ;;
  # An observation that writes, and a fingerprint that never repeats itself.
  inspect)
    count=0
    [ -f "$state_dir/probes" ] && count=$(cat "$state_dir/probes")
    count=$((count + 1))
    echo "$count" >"$state_dir/probes"
    printf 'probe=%s\n' "$count"
    ;;
  *) echo "unknown operation: $operation" >&2; exit 2 ;;
esac
"#;

    /// Conformant in every respect except the one only containment can observe: `apply` starts its
    /// workload INSIDE the invocation's process tree and lets it keep the inherited stdout/stderr.
    /// On a real node the agent's `kill_tree` after a successful `apply` kills it, so this hook
    /// deploys once and loses its workload immediately.
    const LEAKS_WORKLOAD: &str = r#"#!/bin/sh
set -eu
operation=$1; shift
protocol= attempt= state_dir= result_file=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --attempt-id) attempt=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --result-file) result_file=$2; shift 2 ;;
    --reason|--install-root|--candidate|--candidate-version|--output-dir|--input-dir|--predecessor|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "$protocol" = 1 ] || exit 2
case "$operation" in
  apply|rollback)
    marker="$state_dir/$operation.$attempt.done"
    if [ -f "$marker" ]; then
      printf '%s' '{"schema":1,"status":"succeeded","changed":false,"hostAction":"none","message":null}' >"$result_file"
      exit 0
    fi
    # The defect: no `setsid`, no stdio redirection. The "workload" stays in the tree.
    sleep 300 &
    : >"$marker"
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$result_file"
    ;;
  healthcheck) ;;
  inspect) printf 'state=ready\n' ;;
  *) echo "unknown operation: $operation" >&2; exit 2 ;;
esac
"#;

    fn fixture(directory: &Path, name: &str, body: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Every run is scoped to the test's own directory, so a failing check keeps its evidence
    /// there and nothing outlives the test.
    fn check(scratch: &Path, hook: PathBuf) -> Result<(), Error> {
        reconciler_check(ReconcilerCheckArgs {
            hook,
            scratch: Some(scratch.join("scratch")),
            publisher_args: vec!["--publisher-flag".into()],
        })
    }

    #[test]
    fn a_conformant_reconciler_passes_every_check() {
        let scratch = tempfile::tempdir().unwrap();
        let hook = fixture(scratch.path(), "conformant.sh", CONFORMANT);
        check(scratch.path(), hook).expect("a conformant reconciler passes");
    }

    /// The defects this harness exists to catch: a replayed `apply` that fails, a `rollback` that
    /// fails its own replay, an `inspect` that writes to the state directory, and a fingerprint
    /// that changes while nothing has.
    #[test]
    fn a_reconciler_that_breaks_idempotence_is_reported_and_exits_non_zero() {
        let scratch = tempfile::tempdir().unwrap();
        let hook = fixture(scratch.path(), "broken.sh", BREAKS_IDEMPOTENCE);
        let error = check(scratch.path(), hook).expect_err("a non-idempotent reconciler fails");
        assert_eq!(error.to_string(), "4 of 13 conformance checks failed");
    }

    /// The obligation no amount of argv checking can reach: `docs/node-reconciler-protocol.md`
    /// requires a hook to detach anything meant to outlive `apply`, because the agent tears the
    /// invocation's process tree down on EVERY exit path, success included. Invoking through a bare
    /// `Command::output()` gave the harness no tree to tear down, so this hook passed conformance
    /// and then lost its workload to its own first real deployment — and it hung that harness on
    /// the way, since `output()` reads to EOF and the leaked child holds the pipes for 300s with
    /// nothing to break the wait. Both are fixed by the same containment: the run must finish, and
    /// it must finish by REPORTING this.
    #[test]
    fn a_reconciler_that_leaves_its_workload_inside_the_tree_is_reported() {
        let scratch = tempfile::tempdir().unwrap();
        let hook = fixture(scratch.path(), "leaks.sh", LEAKS_WORKLOAD);
        let error = check(scratch.path(), hook).expect_err("a hook that leaks its workload fails");
        assert_eq!(error.to_string(), "1 of 13 conformance checks failed");
    }

    /// The harness must hand the hook exactly the published grammar — a hook that rejects an
    /// unrecognized flag (as the documented minimal reconciler does) is the check on that.
    #[test]
    fn the_harness_sends_only_the_published_flags() {
        let scratch = tempfile::tempdir().unwrap();
        let hook = fixture(scratch.path(), "conformant.sh", CONFORMANT);
        let harness = Harness::new(scratch.path(), hook, Vec::new()).unwrap();
        let invocation = harness
            .invoke(
                Operation::Inspect,
                "1",
                updated_contracts::reconciler::attempt::FINGERPRINT,
                Reason::Restart,
                &harness.candidate,
                &harness.predecessor,
            )
            .unwrap();
        assert!(invocation.succeeded(), "{}", invocation.stderr);
        for flag in FLAGS {
            assert!(
                invocation.argv.contains(flag),
                "the harness omitted {flag} from {}",
                invocation.argv
            );
        }
    }

    /// A hook that answers the protocol but records the environment it was given, so the harness's
    /// own invocation environment can be inspected.
    const REPORTS_ENVIRONMENT: &str = r#"#!/bin/sh
set -eu
operation=$1; shift
state_dir=
while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) state_dir=$2; shift 2 ;;
    --protocol|--attempt-id|--reason|--install-root|--candidate|--candidate-version|--output-dir|--result-file|--input-dir|--predecessor|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
printf '%s' "${PATH-}" >"$state_dir/path"
printf 'state=ready\n'
"#;

    /// The harness must invoke with the AGENT's environment, not merely its argv. It used to spawn
    /// with a bare `env_clear()`, which is stricter than any real node: a hook that execs a helper
    /// by name — from Python, Go, or anything that is not a shell substituting its own default —
    /// failed conformance and then worked in production, and on Windows nothing needing
    /// `SystemRoot` could start at all.
    #[test]
    fn the_harness_invokes_with_the_agents_own_invocation_environment() {
        let scratch = tempfile::tempdir().unwrap();
        let hook = fixture(scratch.path(), "reports-env.sh", REPORTS_ENVIRONMENT);
        let harness = Harness::new(scratch.path(), hook, Vec::new()).unwrap();
        let invocation = harness
            .invoke(
                Operation::Inspect,
                "1",
                updated_contracts::reconciler::attempt::FINGERPRINT,
                Reason::Restart,
                &harness.candidate,
                &harness.predecessor,
            )
            .unwrap();
        assert!(invocation.succeeded(), "{}", invocation.stderr);

        let mut expected = Command::new("hook");
        updated::reconciler::apply_environment(&mut expected);
        let baseline = expected
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("PATH"))
            .and_then(|(_, value)| value)
            .expect("the agent's environment names a search path")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            std::fs::read_to_string(harness.state_dir.join("path")).unwrap(),
            baseline,
            "the hook saw a different PATH than the agent hands one"
        );
    }

    /// A mutation anywhere in the tree moves the digest — that is the whole basis of the
    /// observation check.
    #[test]
    fn the_state_tree_digest_covers_names_and_contents() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a"), b"one").unwrap();
        let original = tree_digest(root).unwrap();
        std::fs::write(root.join("sub/a"), b"two").unwrap();
        assert_ne!(original, tree_digest(root).unwrap(), "contents count");
        std::fs::write(root.join("sub/a"), b"one").unwrap();
        assert_eq!(original, tree_digest(root).unwrap());
        std::fs::rename(root.join("sub/a"), root.join("sub/b")).unwrap();
        assert_ne!(original, tree_digest(root).unwrap(), "names count");
    }

    #[cfg(unix)]
    #[test]
    fn the_tree_file_reader_never_follows_a_replaced_entry() {
        use std::os::unix::fs::symlink;

        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("state");
        let outside = scratch.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("value"), b"state outside the observation tree").unwrap();
        let redirected_parent = root.join("redirected-parent");
        symlink(&outside, &redirected_parent).unwrap();

        let mut digest = updated_contracts::digest::Sha256Hasher::new();
        assert!(
            digest_regular_file(&root, &redirected_parent.join("value"), &mut digest,).is_err()
        );
    }
}
