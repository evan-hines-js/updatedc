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
//! So this exercises them directly: it builds a scratch install root and state directory, invokes
//! the hook through the *same* argv builder shape the agent uses — the published
//! [`FLAGS`](updated_contracts::reconciler::FLAGS) array, positionally paired with its values, with
//! a cleared environment and a null stdin — and replays every operation the way crash recovery
//! does, under the same attempt id.
//!
//! It is deliberately not a test framework: one linear run, one human-readable line per check, and
//! a non-zero exit if any check fails.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use clap::Args;
use updated_contracts::reconciler::{Operation, Reason, FLAGS};
use updated_contracts::telemetry::OutputManifest;

use crate::Error;

/// The transaction token both directions of the checked transaction are keyed to. The compensating
/// direction is the agent's own derivation (`Transaction::rollback_attempt_id`): the forward token
/// with `r` appended.
const ATTEMPT: &str = "conformance1";

/// The versions the scratch releases carry. Two different ones, so a hook that reads
/// `--candidate-version` and `--predecessor-version` cannot pass by accident.
const CANDIDATE_VERSION: &str = "2.0.0";
const PREDECESSOR_VERSION: &str = "1.0.0";

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
/// passes exists before the first invocation, and `--output-file`'s parent exists so a hook can
/// write its manifest without creating directories.
struct Harness {
    hook: PathBuf,
    cwd: PathBuf,
    install_root: PathBuf,
    state_dir: PathBuf,
    output_file: PathBuf,
    input_file: PathBuf,
    candidate: Release,
    predecessor: Release,
    publisher_args: Vec<String>,
}

/// What one invocation did: enough to name it in a failure and to compare it against its replay.
struct Invocation {
    argv: String,
    /// The exit status as the agent reads it — `Some(code)`, or `None` for death by signal.
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

impl Invocation {
    fn succeeded(&self) -> bool {
        self.code == Some(0)
    }

    /// How the invocation ended, for the report line.
    fn status(&self) -> String {
        match self.code {
            Some(code) => format!("exit {code}"),
            None => "killed by a signal".to_string(),
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
        // The agent's own layout: the reconciler's private state directory is per product under the
        // install root, and outputs are partitioned by the candidate's immutable identity.
        let state_dir = install_root.join("providers/state/conformance");
        let output_file = install_root
            .join("providers/outputs")
            .join(format!("{}.json", "0".repeat(64)));
        let candidate = install_root
            .join("versions")
            .join(format!("{CANDIDATE_VERSION}-candidate"));
        let predecessor = install_root
            .join("versions")
            .join(format!("{PREDECESSOR_VERSION}-predecessor"));
        let outputs = output_file
            .parent()
            .expect("the outputs path has a parent")
            .to_path_buf();
        for directory in [&state_dir, &candidate, &predecessor, &outputs] {
            std::fs::create_dir_all(directory)?;
        }
        // The typed inputs a prerequisite group resolves into the deployment. Empty here — this
        // harness has no control plane — but present, because the agent always writes it and a hook
        // is entitled to open it.
        let input_file = state_dir.join("inputs.json");
        std::fs::write(&input_file, b"{}")?;
        Ok(Harness {
            cwd: hook
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf(),
            hook,
            install_root,
            state_dir,
            output_file,
            input_file,
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

    /// Invoke the hook exactly as `agent::update::prepare_lifecycle_command` does.
    ///
    /// `converge_onto` is always `--candidate` — in both directions, per the protocol: a rollback
    /// passes the release being restored as the candidate and the failed one as the predecessor.
    /// The flag names come from the published grammar itself, positionally paired with their values,
    /// so this harness cannot check a hook against a flag the agent does not send.
    fn invoke(
        &self,
        operation: &str,
        protocol: &str,
        attempt_id: &str,
        reason: Reason,
        converge_onto: &Release,
        undoing: &Release,
    ) -> io::Result<Invocation> {
        let values: [&OsStr; FLAGS.len()] = [
            OsStr::new(protocol),
            OsStr::new(attempt_id),
            OsStr::new(reason.as_str()),
            self.install_root.as_os_str(),
            self.state_dir.as_os_str(),
            converge_onto.dir.as_os_str(),
            OsStr::new(converge_onto.version),
            self.output_file.as_os_str(),
            self.input_file.as_os_str(),
            undoing.dir.as_os_str(),
            OsStr::new(undoing.version),
        ];
        let mut command = Command::new(&self.hook);
        command.arg(operation);
        let mut argv = vec![self.hook.display().to_string(), operation.to_string()];
        for (flag, value) in FLAGS.iter().zip(values) {
            command.arg(flag).arg(value);
            argv.push((*flag).to_string());
            argv.push(value.to_string_lossy().into_owned());
        }
        if !self.publisher_args.is_empty() {
            command.arg("--").args(&self.publisher_args);
            argv.push("--".to_string());
            argv.extend(self.publisher_args.iter().cloned());
        }
        // Cleared environment and null stdin, like the real invocation. Assigned secrets would be
        // added here on a real node; a conformance run has none, so a hook that silently depends on
        // one fails here rather than on the first machine that deploys it.
        command
            .current_dir(&self.cwd)
            .env_clear()
            .stdin(std::process::Stdio::null());
        let Output {
            status,
            stdout,
            stderr,
        } = command.output()?;
        Ok(Invocation {
            argv: argv.join(" "),
            code: status.code(),
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    /// The bytes of the output manifest, if the hook wrote one.
    fn manifest(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.output_file).ok()
    }
}

/// A digest over the whole state-directory tree: every path, its kind, and every file's contents.
///
/// This is what makes "an observation must not mutate" checkable. Names are included as well as
/// contents, so a hook that deletes one scratch file and writes another of the same size is still
/// caught.
fn tree_digest(root: &Path) -> io::Result<String> {
    fn walk(root: &Path, at: &Path, material: &mut Vec<u8>) -> io::Result<()> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(at)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<_>>()?;
        // Directory order is not defined; the digest must be.
        entries.sort();
        for entry in entries {
            let relative = entry.strip_prefix(root).unwrap_or(&entry);
            material.extend_from_slice(relative.as_os_str().as_encoded_bytes());
            material.push(0);
            let kind = std::fs::symlink_metadata(&entry)?.file_type();
            if kind.is_dir() {
                material.extend_from_slice(b"dir\0");
                walk(root, &entry, material)?;
            } else if kind.is_file() {
                material.extend_from_slice(b"file\0");
                material.extend_from_slice(&std::fs::read(&entry)?);
            } else {
                material.extend_from_slice(b"other\0");
            }
            material.push(0);
        }
        Ok(())
    }
    let mut material = Vec::new();
    walk(root, root, &mut material)?;
    Ok(updated::hash::sha256_bytes(&material))
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
        "checking {} against node reconciler protocol 1\n  install root: {}\n  state dir:    {}\n",
        harness.hook.display(),
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
        Operation::Apply.as_str(),
        "1",
        ATTEMPT,
        Reason::Install,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "apply/install succeeds",
        first.succeeded(),
        format!(
            "{}{}\n        {}",
            first.status(),
            first.diagnostic(),
            first.argv
        ),
    );
    let first_manifest = harness.manifest();
    let replay = harness.invoke(
        Operation::Apply.as_str(),
        "1",
        ATTEMPT,
        Reason::Install,
        &harness.candidate,
        &harness.predecessor,
    )?;
    report.check(
        "apply is replay-tolerant (same attempt id, run twice)",
        replay.succeeded(),
        format!(
            "first {}, replay {}{}",
            first.status(),
            replay.status(),
            replay.diagnostic()
        ),
    );
    let replayed_manifest = harness.manifest();
    match (&first_manifest, &replayed_manifest) {
        (None, _) => report.check(
            "output manifest",
            true,
            format!(
                "no manifest written to {}; this release declares no outputs",
                harness.output_file.display()
            ),
        ),
        (Some(bytes), replayed) => {
            let parsed = serde_json::from_slice::<OutputManifest>(bytes)
                .map_err(|error| error.to_string())
                .and_then(|manifest| manifest.validate().map_err(|error| error.to_string()));
            report.check(
                "output manifest parses under the published bounds",
                parsed.is_ok(),
                match &parsed {
                    Ok(()) => format!("{} bytes accepted", bytes.len()),
                    Err(error) => format!("rejected: {error}"),
                },
            );
            report.check(
                "output manifest is byte-identical across the replay",
                replayed.as_ref() == Some(bytes),
                match replayed {
                    Some(after) if after == bytes => format!("{} bytes, unchanged", bytes.len()),
                    Some(after) => format!(
                        "{} bytes before the replay, {} after: a replayed apply must not \
                         re-derive its outputs",
                        bytes.len(),
                        after.len()
                    ),
                    None => "the replay deleted the manifest".to_string(),
                },
            );
        }
    }

    // Observations. The agent repeats these freely and may have both in flight at once, so each
    // must answer consistently and neither may write.
    let before = tree_digest(&harness.state_dir)?;
    let health: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Healthcheck.as_str(),
                "1",
                updated_contracts::reconciler::attempt::PERIODIC,
                Reason::Restart,
                &harness.candidate,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "healthcheck answers consistently across a repeated probe",
        health[0].code == health[1].code,
        format!(
            "{} then {}{}",
            health[0].status(),
            health[1].status(),
            health[1].diagnostic()
        ),
    );
    let inspect: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Inspect.as_str(),
                "1",
                updated_contracts::reconciler::attempt::FINGERPRINT,
                Reason::Restart,
                &harness.candidate,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "inspect answers consistently across a repeated probe",
        inspect[0].code == inspect[1].code,
        format!(
            "{} then {}{}",
            inspect[0].status(),
            inspect[1].status(),
            inspect[1].diagnostic()
        ),
    );
    // Non-empty stdout is the fingerprint material; a fingerprint that changes while nothing has
    // changed re-arms the fleet's drift detection on every probe.
    report.check(
        "inspect writes stable, non-empty fingerprint material to stdout",
        !inspect[0].stdout.is_empty() && inspect[0].stdout == inspect[1].stdout,
        if inspect[0].stdout.is_empty() {
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
    let rollback_attempt = format!("{ATTEMPT}r");
    let rollback: Vec<Invocation> = (0..2)
        .map(|_| {
            harness.invoke(
                Operation::Rollback.as_str(),
                "1",
                &rollback_attempt,
                Reason::Update,
                &harness.predecessor,
                &harness.candidate,
            )
        })
        .collect::<io::Result<_>>()?;
    report.check(
        "rollback is replay-tolerant (compensating attempt id, run twice)",
        rollback[0].code == rollback[1].code,
        format!(
            "--attempt-id {rollback_attempt}, --candidate {} (restored), --predecessor {} \
             (failed): {} then {}{}",
            harness.predecessor.version,
            harness.candidate.version,
            rollback[0].status(),
            rollback[1].status(),
            rollback[1].diagnostic()
        ),
    );

    // The two refusals. A hook that runs whatever it is handed is a hook that will one day converge
    // a machine on a protocol it does not implement.
    let unknown = harness.invoke(
        "converge",
        "1",
        ATTEMPT,
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
        Operation::Apply.as_str(),
        "2",
        ATTEMPT,
        Reason::Install,
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
protocol= reason= attempt= state_dir= output_file=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --attempt-id) attempt=$2; shift 2 ;;
    --reason) reason=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --output-file) output_file=$2; shift 2 ;;
    --install-root|--candidate|--candidate-version|--input-file|--predecessor|--predecessor-version)
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
    [ -f "$marker" ] && exit 0
    printf '{"schema":1,"values":{"endpoint":{"type":"string","value":"https://svc:8200"}}}' \
      >"$output_file"
    : >"$marker"
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
protocol= state_dir=
while [ $# -gt 0 ]; do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --attempt-id|--reason|--install-root|--candidate|--candidate-version|--output-file|--input-file|--predecessor|--predecessor-version)
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
        assert_eq!(error.to_string(), "4 of 10 conformance checks failed");
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
                Operation::Inspect.as_str(),
                "1",
                ATTEMPT,
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
}
