//! THE environment every node reconciler invocation runs with.
//!
//! The other half of the published invocation contract — the flag grammar and the one builder that
//! binds a value to a flag — is [`updated_contracts::reconciler`]. It cannot own this half:
//! that crate deliberately contains no process behavior, and this is a `std::process::Command`
//! mutation that also reads the ambient environment. So the environment lives here, one crate up,
//! where both invokers already are: the agent's `update::prepare_lifecycle_command` and
//! `updatectl reconciler-check`.
//!
//! One chokepoint, because a harness that is *stricter* than production certifies hooks that then
//! fail on a real node, and one that is *looser* passes hooks that depend on something the agent
//! never supplies. Both were live: the harness spawned with a bare `env_clear()`, so on Windows a
//! hook had no `SystemRoot` and could not start PowerShell or cmd at all, and on Unix it had no
//! `PATH` — surviving only because `/bin/sh` substitutes a default, and failing outright for a hook
//! that execs by name from a non-shell runtime.

use std::{io, path::Path, process::Command};

/// Maximum stdout or stderr retained from one reconciler invocation.
///
/// Both the agent and `updatectl reconciler-check` use [`capture_output`]; a hook therefore cannot
/// consume unbounded memory in either invoker, and the harness certifies the same fingerprint
/// ceiling production enforces.
pub const OUTPUT_LIMIT: usize = 64 * 1024;

/// The only two legal answers from a completed reconciler process. A mutation always carries its
/// validated document; an observation is structurally incapable of carrying one.
#[derive(Debug, PartialEq, Eq)]
pub enum InvocationResult {
    Mutation(updated_contracts::reconciler::ResultDocument),
    Observation,
}

/// Consume the structured answer for one reconciler invocation.
///
/// State-changing operations must answer exactly once. Observations are intentionally incapable of
/// asking the platform to mutate or reboot the host, so a result file from either observation is a
/// protocol violation rather than an ignored request.
pub fn take_result(
    path: &Path,
    operation: updated_contracts::reconciler::Operation,
) -> io::Result<InvocationResult> {
    use updated_contracts::reconciler::ResultDocument;

    let bytes = match foundation::file::read_bounded_regular(
        path,
        updated_contracts::reconciler::MAX_RESULT_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    match (operation.mutation(), bytes) {
        (Some(_), None) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reconciler {operation} produced no structured result"),
        )),
        (None, Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("observation operation {operation} must not produce a structured result"),
        )),
        (None, None) => Ok(InvocationResult::Observation),
        (Some(_), Some(bytes)) => {
            let result = ResultDocument::from_bounded_json(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            std::fs::remove_file(path)?;
            Ok(InvocationResult::Mutation(result))
        }
    }
}

/// Durably replace the platform-owned audit record only after a state-changing invocation has
/// supplied a complete successful result.
pub fn write_last_reconciliation(
    path: &Path,
    record: &updated_contracts::reconciler::LastReconciliation,
) -> io::Result<()> {
    let bytes = record
        .to_bounded_json()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    foundation::durable::atomic_write_managed(path, ".reconciliation-", &bytes)
}

/// Load the last successful reconciliation. Absence is valid before the first mutation; malformed
/// persisted evidence is an error rather than a silently trusted report.
pub fn read_last_reconciliation(
    path: &Path,
) -> io::Result<Option<updated_contracts::reconciler::LastReconciliation>> {
    let bytes = match foundation::file::read_bounded_regular(
        path,
        updated_contracts::reconciler::LastReconciliation::MAX_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    updated_contracts::reconciler::LastReconciliation::from_bounded_json(&bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// The bounded result of asynchronously draining one reconciler pipe: retained bytes and whether
/// anything beyond [`OUTPUT_LIMIT`] was discarded.
pub type OutputCapture = std::sync::mpsc::Receiver<io::Result<(Vec<u8>, bool)>>;

/// Drain one reconciler pipe on a dedicated thread while retaining at most [`OUTPUT_LIMIT`].
///
/// A channel makes the reader abandonable: joining a reader whose pipe is held open by an escaped
/// descendant would let that descendant defeat the invocation deadline. The caller chooses how
/// long EOF gets after tearing down the process tree.
pub fn capture_output(mut input: impl io::Read + Send + 'static) -> OutputCapture {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        let outcome = loop {
            match input.read(&mut buffer) {
                Ok(0) => break Ok((captured, truncated)),
                Ok(read) => {
                    let remaining = OUTPUT_LIMIT.saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..read.min(remaining)]);
                    truncated |= read > remaining;
                }
                Err(error) => break Err(error),
            }
        };
        let _ = sender.send(outcome);
    });
    receiver
}

/// Clear `command`'s environment and give it exactly the minimum needed to find an interpreter.
///
/// The clearing is part of it, not the caller's job — an invoker that forgot it would leak the
/// agent's own environment into a hook, and the difference is invisible until something in it
/// matters. Application configuration—including secrets—exists only as named files under the
/// invocation's input directory; there is no scalar/environment representation to drift from it.
pub fn apply_environment(command: &mut Command) {
    command.env_clear();

    #[cfg(unix)]
    command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");

    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        let system32 = std::path::PathBuf::from(&system_root).join("System32");
        let powershell = system32.join("WindowsPowerShell/v1.0");
        command
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env(
                "PATH",
                std::env::join_paths([system32, powershell]).unwrap_or_default(),
            );
        for name in ["TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
}

/// Read one flat directory of ordinary files into the bounded wire snapshot.
///
/// This is the single filesystem-to-dataflow boundary used by both the agent and the conformance
/// harness. Symlinks, directories, non-UTF-8 names, and oversize files are hard failures.
pub fn snapshot_directory(
    directory: &Path,
) -> io::Result<updated_contracts::dataflow::FileSnapshot> {
    use updated_contracts::dataflow::{FileSnapshot, FileValue};

    let mut snapshot = FileSnapshot::default();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if snapshot.files.len() == FileSnapshot::MAX_FILES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reconciler output directory has too many files",
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 output name"))?;
        if !FileSnapshot::valid_name(&name) || !entry.file_type()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("reconciler output {name:?} is not a permitted regular file"),
            ));
        }
        // The shared primitive makes the opened handle—not advisory path metadata—the authority
        // for both the file type and the byte limit.
        let bytes = foundation::file::read_bounded_regular(
            &entry.path(),
            FileValue::MAX_BYTES,
            foundation::file::FinalSymlink::Refuse,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read reconciler output {name:?}: {error}"),
            )
        })?;
        let value = FileValue::from_bytes(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        snapshot.files.insert(name, value);
    }
    snapshot
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(snapshot)
}

/// Retain only the output snapshots that the installed state can still publish or roll back to.
///
/// This directory is wholly agent-owned and its values may be credentials. Unknown entries and
/// interrupted-write leftovers are therefore garbage, not operator data to preserve. Each removal
/// uses the durable path primitive, which removes a symlink itself rather than following it.
pub fn prune_output_snapshots(
    paths: &crate::config::Paths,
    protected_archive_sha256: &[String],
) -> io::Result<usize> {
    let protected: std::collections::BTreeSet<_> = protected_archive_sha256
        .iter()
        .map(|digest| paths.reconciler_output_snapshot(digest))
        .collect();
    let entries = match std::fs::read_dir(&paths.provider_outputs) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0usize;
    for entry in entries {
        let path = entry?.path();
        if !protected.contains(&path) {
            foundation::durable::remove_path(&path)?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_result(path: &Path, result: &updated_contracts::reconciler::ResultDocument) {
        std::fs::write(path, result.to_bounded_json().unwrap()).unwrap();
    }

    #[test]
    fn mutations_require_a_structured_result_and_observations_forbid_one() {
        use updated_contracts::reconciler::{HostAction, Operation, ResultDocument, ResultStatus};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        assert_eq!(
            take_result(&path, Operation::Apply).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let result = ResultDocument {
            schema: ResultDocument::SCHEMA,
            status: ResultStatus::Succeeded,
            changed: true,
            host_action: HostAction::None,
            retry_after_seconds: None,
            message: None,
        };
        write_result(&path, &result);
        assert_eq!(
            take_result(&path, Operation::Apply).unwrap(),
            InvocationResult::Mutation(result)
        );
        assert!(!path.exists());

        write_result(
            &path,
            &ResultDocument {
                schema: ResultDocument::SCHEMA,
                status: ResultStatus::Succeeded,
                changed: false,
                host_action: HostAction::None,
                retry_after_seconds: None,
                message: None,
            },
        );
        assert_eq!(
            take_result(&path, Operation::Healthcheck)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn the_last_reconciliation_is_durable_bounded_and_validated_on_read() {
        use updated_contracts::reconciler::{
            HostAction, LastReconciliation, Operation, Reason, ReconciledRelease,
            ReconcilerIdentity, ResultDocument, ResultStatus,
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reconciliation.json");
        assert_eq!(read_last_reconciliation(&path).unwrap(), None);
        let record = LastReconciliation {
            schema: LastReconciliation::SCHEMA,
            operation: Operation::Rollback,
            reason: Reason::Update,
            attempt_id: format!("{}r", "a".repeat(64)),
            candidate: ReconciledRelease {
                version: "1.0.0".into(),
                manifest_sha256: "a".repeat(64),
                archive_sha256: "b".repeat(64),
            },
            predecessor: ReconciledRelease {
                version: "2.0.0".into(),
                manifest_sha256: "c".repeat(64),
                archive_sha256: "d".repeat(64),
            },
            reconciler: ReconcilerIdentity {
                provider_set_sha256: "e".repeat(64),
                product: "system".into(),
                release: ReconciledRelease {
                    version: "3.0.0".into(),
                    manifest_sha256: "f".repeat(64),
                    archive_sha256: "0".repeat(64),
                },
            },
            result: ResultDocument {
                schema: ResultDocument::SCHEMA,
                status: ResultStatus::Succeeded,
                changed: true,
                host_action: HostAction::None,
                retry_after_seconds: None,
                message: Some("restored predecessor".into()),
            },
            completed_at_ms: 1,
        };
        write_last_reconciliation(&path, &record).unwrap();
        assert_eq!(read_last_reconciliation(&path).unwrap(), Some(record));

        std::fs::write(&path, b"{}").unwrap();
        assert_eq!(
            read_last_reconciliation(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    use std::collections::BTreeMap;

    #[test]
    fn output_capture_retains_one_shared_bounded_prefix() {
        let input = vec![b'x'; OUTPUT_LIMIT + 1];
        let (captured, truncated) = capture_output(std::io::Cursor::new(input))
            .recv()
            .unwrap()
            .unwrap();
        assert_eq!(captured.len(), OUTPUT_LIMIT);
        assert!(truncated);
    }

    /// The properties every invoker depends on: nothing ambient survives, an interpreter is
    /// findable, a secret wins over whatever ambient name it collides with, and no value the
    /// chokepoint contributes can land in argv — which is world-readable in `ps` on every platform
    /// this runs on.
    #[test]
    fn the_invocation_environment_is_cleared_and_carries_a_search_path() {
        let mut command = Command::new("hook");
        command
            .env("AMBIENT", "leaked")
            .env("PATH", "/opt/ambient")
            .env("TOKEN", "ambient");
        apply_environment(&mut command);
        let environment: BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(name, value)| {
                Some((
                    name.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();

        assert!(
            !environment.contains_key("AMBIENT"),
            "the agent's own environment must not reach a hook: {environment:?}"
        );
        assert!(!environment.contains_key("TOKEN"));
        let path = environment
            .get("PATH")
            .expect("a hook can find an interpreter");
        assert_ne!(
            path, "/opt/ambient",
            "the baseline replaces an ambient PATH"
        );
        #[cfg(unix)]
        assert_eq!(path, "/usr/sbin:/usr/bin:/sbin:/bin");
        assert!(
            command.get_args().next().is_none(),
            "the chokepoint contributes no arguments, so no secret can land in argv"
        );
    }

    #[test]
    fn snapshot_directory_accepts_only_flat_bounded_regular_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("endpoint"), b"https://service.internal").unwrap();
        let snapshot = snapshot_directory(root.path()).unwrap();
        assert_eq!(snapshot.files.len(), 1);

        std::fs::create_dir(root.path().join("nested")).unwrap();
        assert_eq!(
            snapshot_directory(root.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        std::fs::remove_dir(root.path().join("nested")).unwrap();
        std::fs::write(
            root.path().join("oversized"),
            vec![0; updated_contracts::dataflow::FileValue::MAX_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            snapshot_directory(root.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn output_snapshot_gc_keeps_only_active_and_rollback_protected_values() {
        let root = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::resolve(root.path(), &root.path().join("enrollment"));
        std::fs::create_dir_all(&paths.provider_outputs).unwrap();
        let active = "a".repeat(64);
        let rollback = "b".repeat(64);
        let stale = paths.reconciler_output_snapshot(&"c".repeat(64));
        for path in [
            paths.reconciler_output_snapshot(&active),
            paths.reconciler_output_snapshot(&rollback),
            stale.clone(),
        ] {
            std::fs::write(path, b"possibly secret").unwrap();
        }
        std::fs::create_dir(paths.provider_outputs.join("interrupted-write")).unwrap();

        assert_eq!(
            prune_output_snapshots(&paths, &[active.clone(), rollback.clone()]).unwrap(),
            2
        );
        assert!(paths.reconciler_output_snapshot(&active).is_file());
        assert!(paths.reconciler_output_snapshot(&rollback).is_file());
        assert!(!stale.exists());
        assert!(!paths.provider_outputs.join("interrupted-write").exists());
    }
}
