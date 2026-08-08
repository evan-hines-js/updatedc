//! The guardian's durable state, in tiny frozen text formats.
//!
//! The guardian keeps almost nothing, and interprets none of it. It moves one pointer —
//! which supervisor binary is committed (`desired-supervisor`) — forward on a successful
//! handoff and leaves it put on a failed one (that is the rollback). And it drops
//! two dumb markers for the supervisor to interpret on recovery: `service-exited` (the
//! managed service exited spontaneously) and `rejected-supervisor` (a candidate failed
//! its readiness gate). It keeps no rejection set and no application-ownership record —
//! the guardian owns the app in memory, and the app never outlives the guardian.
//!
//! State-dir paths are required to be valid UTF-8 (checked at startup), so these files
//! are plain text.

use std::path::{Path, PathBuf};

/// The committed-supervisor pointer's filename and text format live in `control`: the supervisor
/// reads the same file (its staging GC must not delete the guardian's rollback target), so the
/// layout is a cross-process contract rather than guardian-private state.
const DESIRED_FILE: &str = control::DESIRED_SUPERVISOR_FILE;
const SEEDED_FILE: &str = "seeded-supervisor";

/// The committed supervisor binary path. `None` on first boot (the installer or the
/// `--supervisor` flag seeds it).
pub fn desired_supervisor(state_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    read_pointer(&state_dir.join(DESIRED_FILE))
}

pub fn set_desired_supervisor(state_dir: &Path, path: &Path) -> std::io::Result<()> {
    write_pointer(&state_dir.join(DESIRED_FILE), path)
}

/// The initial supervisor path recorded at first-boot seed. It lives *outside* the
/// content-addressed staging tree (the installer placed it), so validation of the committed
/// pointer trusts a non-staging path only when it matches this durable record — proving a prior
/// boot legitimately seeded it while `--supervisor` was present, rather than requiring the flag to
/// be re-passed on every restart (which would brick a node that never self-updated).
pub fn seeded_supervisor(state_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    read_pointer(&state_dir.join(SEEDED_FILE))
}

pub fn set_seeded_supervisor(state_dir: &Path, path: &Path) -> std::io::Result<()> {
    write_pointer(&state_dir.join(SEEDED_FILE), path)
}

fn read_pointer(path: &Path) -> std::io::Result<Option<PathBuf>> {
    control::read_supervisor_pointer(path)
}

/// Every file here is *managed* state, not a secret: the guardian may run as SYSTEM while the
/// supervisor runs as the service account, and the installer grants that account access to the
/// state directory by inheritance alone. A privately-ACLed write would commit a pointer or
/// marker the supervisor could neither read nor replace, with no `icacls` grant able to repair it.
fn write_pointer(path: &Path, target: &Path) -> std::io::Result<()> {
    let body = control::encode_supervisor_pointer(target)?;
    foundation::durable::atomic_write_managed(path, ".guardian-", body.as_bytes())
}

/// Note that the managed service exited spontaneously with `code` (the guardian rolled its code
/// up). The supervisor reads and clears this on recovery to revert an unconfirmed update.
/// A requested stop leaves it untouched, distinguishing spontaneous exit from a clean
/// service restart.
///
/// Each exit is a distinct event, so each marker says so in its own bytes: the exit code plus a
/// fresh stamp. The supervisor never parses this — it compares the bytes, and that is the ONLY
/// thing that tells the instance it read from one the guardian wrote while it was still
/// reconciling. (Filesystem metadata cannot: an empty marker's length never varies, and on Windows
/// NTFS tunneling restores the creation time across the temp+rename an atomic write performs.)
/// Clearing a marker it never read would drop the record of a crash inside a confirmation window
/// and let the bad update be confirmed.
pub fn mark_service_exited(state_dir: &Path, code: i32) -> std::io::Result<()> {
    // Durable (atomic write + fsync), like the desired pointer: a lost exit marker could
    // let an unconfirmed, immediately-exiting service return unreverted after reboot.
    let stamp = format!("{code} {}", crate::rand::to_hex(&crate::rand::nonce()));
    foundation::durable::atomic_write_managed(
        &state_dir.join(control::SERVICE_EXITED_MARKER_FILE),
        ".guardian-",
        stamp.as_bytes(),
    )
}

/// Note the path of a candidate supervisor that failed its readiness gate, for the
/// supervisor to read and reject on recovery. The guardian records the fact and forgets
/// it — what to do about it (skip that release forever) is the supervisor's policy.
pub fn mark_rejected_supervisor(state_dir: &Path, candidate: &Path) -> std::io::Result<()> {
    if let Some(s) = candidate.to_str() {
        // Durable + atomic so a crash mid-write can't leave a truncated path and a power
        // loss can't drop the rejection (which would let the bad candidate be re-staged).
        foundation::durable::atomic_write_managed(
            &state_dir.join(control::REJECTED_SUPERVISOR_FILE),
            ".guardian-",
            s.as_bytes(),
        )
    } else {
        Err(std::io::Error::other(
            "rejected supervisor path is not valid UTF-8",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let d = guard.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        (guard, d)
    }

    #[test]
    fn desired_supervisor_pointer_round_trips() {
        let (_tmp, d) = dir("desired");
        assert!(desired_supervisor(&d).unwrap().is_none());
        let p = d.join("supervisors/deadbeef/supervisor");
        set_desired_supervisor(&d, &p).unwrap();
        assert_eq!(desired_supervisor(&d).unwrap(), Some(p));
    }

    #[test]
    fn corrupt_pointer_is_an_error_not_first_boot() {
        let (_tmp, d) = dir("corrupt-desired");
        std::fs::write(d.join(DESIRED_FILE), b"not-a-pointer\n").unwrap();
        assert_eq!(
            desired_supervisor(&d).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_service_exit_marker_is_distinguishable_from_the_last() {
        // The supervisor tells the instance it read from one written mid-boot by comparing bytes,
        // so two exits must never produce identical content — including two exits with the same
        // code, which is the common case (a crash-looping app).
        let (_tmp, d) = dir("marker-identity");
        let path = d.join(control::SERVICE_EXITED_MARKER_FILE);
        mark_service_exited(&d, 7).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();
        mark_service_exited(&d, 7).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("7 "), "the exit code is legible: {first}");
        assert_eq!(first.lines().count(), 1, "one line: {first}");
    }

    #[test]
    fn markers_are_written_for_the_supervisor_to_interpret() {
        let (_tmp, d) = dir("markers");
        mark_service_exited(&d, 0).unwrap();
        assert!(d.join(control::SERVICE_EXITED_MARKER_FILE).exists());
        let bad = d.join("supervisors/badc0de/supervisor");
        mark_rejected_supervisor(&d, &bad).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join(control::REJECTED_SUPERVISOR_FILE)).unwrap(),
            bad.to_str().unwrap()
        );
    }

    #[test]
    fn marker_write_failures_are_reported() {
        let (_tmp, d) = dir("marker-errors");
        std::fs::create_dir(d.join(control::SERVICE_EXITED_MARKER_FILE)).unwrap();
        assert!(mark_service_exited(&d, 1).is_err());
        std::fs::create_dir(d.join(control::REJECTED_SUPERVISOR_FILE)).unwrap();
        assert!(mark_rejected_supervisor(&d, Path::new("candidate")).is_err());
    }
}
