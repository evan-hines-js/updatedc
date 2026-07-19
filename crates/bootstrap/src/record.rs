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

const DESIRED_FILE: &str = "desired-supervisor";
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
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut lines = text.lines();
    if lines.next() != Some("supervisor-v1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid desired-supervisor header",
        ));
    }
    let p = lines.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "desired-supervisor path is missing",
        )
    })?;
    if p.is_empty() || lines.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "desired-supervisor record is malformed",
        ));
    }
    Ok(Some(PathBuf::from(p)))
}

fn write_pointer(path: &Path, target: &Path) -> std::io::Result<()> {
    let target = target
        .to_str()
        .ok_or_else(|| std::io::Error::other("supervisor path is not valid UTF-8"))?;
    let body = format!("supervisor-v1\n{target}\n");
    foundation::durable::atomic_write(path, ".guardian-", body.as_bytes())
}

/// Note that the managed service exited spontaneously (the guardian rolled its code up).
/// The supervisor reads and clears this on recovery to revert an unconfirmed update.
/// A requested stop leaves it untouched, distinguishing spontaneous exit from a clean
/// service restart.
pub fn mark_service_exited(state_dir: &Path) -> std::io::Result<()> {
    // Durable (atomic write + fsync), like the desired pointer: a lost exit marker could
    // let an unconfirmed, immediately-exiting service return unreverted after reboot.
    foundation::durable::atomic_write(
        &state_dir.join(control::SERVICE_EXITED_MARKER_FILE),
        ".guardian-",
        b"",
    )
}

/// Note the path of a candidate supervisor that failed its readiness gate, for the
/// supervisor to read and reject on recovery. The guardian records the fact and forgets
/// it — what to do about it (skip that release forever) is the supervisor's policy.
pub fn mark_rejected_supervisor(state_dir: &Path, candidate: &Path) -> std::io::Result<()> {
    if let Some(s) = candidate.to_str() {
        // Durable + atomic so a crash mid-write can't leave a truncated path and a power
        // loss can't drop the rejection (which would let the bad candidate be re-staged).
        foundation::durable::atomic_write(
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

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("guardian-record-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn desired_supervisor_pointer_round_trips() {
        let d = dir("desired");
        assert!(desired_supervisor(&d).unwrap().is_none());
        let p = d.join("supervisors/deadbeef/supervisor");
        set_desired_supervisor(&d, &p).unwrap();
        assert_eq!(desired_supervisor(&d).unwrap(), Some(p));
    }

    #[test]
    fn corrupt_pointer_is_an_error_not_first_boot() {
        let d = dir("corrupt-desired");
        std::fs::write(d.join(DESIRED_FILE), b"not-a-pointer\n").unwrap();
        assert_eq!(
            desired_supervisor(&d).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn markers_are_written_for_the_supervisor_to_interpret() {
        let d = dir("markers");
        mark_service_exited(&d).unwrap();
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
        let d = dir("marker-errors");
        std::fs::create_dir(d.join(control::SERVICE_EXITED_MARKER_FILE)).unwrap();
        assert!(mark_service_exited(&d).is_err());
        std::fs::create_dir(d.join(control::REJECTED_SUPERVISOR_FILE)).unwrap();
        assert!(mark_rejected_supervisor(&d, Path::new("candidate")).is_err());
    }
}
