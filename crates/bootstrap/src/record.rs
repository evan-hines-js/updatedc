//! The guardian's durable state, in tiny frozen text formats.
//!
//! The guardian keeps almost nothing, and interprets none of it. It moves one pointer —
//! which supervisor binary is committed (`desired-supervisor`) — forward on a successful
//! handoff and leaves it put on a failed one (that is the rollback). And it drops
//! two dumb markers for the supervisor to interpret on recovery: `app-crashed` (the last
//! application exit was a crash) and `rejected-supervisor` (a candidate supervisor failed
//! its readiness gate). It keeps no rejection set and no application-ownership record —
//! the guardian owns the app in memory, and the app never outlives the guardian.
//!
//! State-dir paths are required to be valid UTF-8 (checked at startup), so these files
//! are plain text.

use std::path::{Path, PathBuf};

use crate::durable;

const DESIRED_FILE: &str = "desired-supervisor";

/// The committed supervisor binary path. `None` on first boot (the installer or the
/// `--supervisor` flag seeds it).
pub fn desired_supervisor(state_dir: &Path) -> Option<PathBuf> {
    read_pointer(&state_dir.join(DESIRED_FILE))
}

pub fn set_desired_supervisor(state_dir: &Path, path: &Path) -> std::io::Result<()> {
    write_pointer(&state_dir.join(DESIRED_FILE), path)
}

fn read_pointer(path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "supervisor-v1" {
        return None;
    }
    let p = lines.next()?;
    (!p.is_empty()).then(|| PathBuf::from(p))
}

fn write_pointer(path: &Path, target: &Path) -> std::io::Result<()> {
    let target = target
        .to_str()
        .ok_or_else(|| std::io::Error::other("supervisor path is not valid UTF-8"))?;
    let body = format!("supervisor-v1\n{target}\n");
    durable::atomic_write(path, body.as_bytes())
}

/// Note that the last application exit was a crash (the guardian rolled its code up).
/// The supervisor reads and clears this on recovery to revert an unconfirmed update.
/// A clean stop leaves it untouched, so it distinguishes a crash-restart from an
/// ordinary service restart.
pub fn mark_app_crashed(state_dir: &Path) {
    // Durable (atomic write + fsync), like the desired pointer: a crash marker lost to
    // power loss would let a crash-looping update come back up unreverted on reboot.
    let _ = durable::atomic_write(&state_dir.join(control::CRASH_MARKER_FILE), b"");
}

/// Note the path of a candidate supervisor that failed its readiness gate, for the
/// supervisor to read and reject on recovery. The guardian records the fact and forgets
/// it — what to do about it (skip that release forever) is the supervisor's policy.
pub fn mark_rejected_supervisor(state_dir: &Path, candidate: &Path) {
    if let Some(s) = candidate.to_str() {
        // Durable + atomic so a crash mid-write can't leave a truncated path and a power
        // loss can't drop the rejection (which would let the bad candidate be re-staged).
        let _ = durable::atomic_write(
            &state_dir.join(control::REJECTED_SUPERVISOR_FILE),
            s.as_bytes(),
        );
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
        assert!(desired_supervisor(&d).is_none());
        let p = d.join("supervisors/deadbeef/supervisor");
        set_desired_supervisor(&d, &p).unwrap();
        assert_eq!(desired_supervisor(&d), Some(p));
    }

    #[test]
    fn markers_are_written_for_the_supervisor_to_interpret() {
        let d = dir("markers");
        mark_app_crashed(&d);
        assert!(d.join(control::CRASH_MARKER_FILE).exists());
        let bad = d.join("supervisors/badc0de/supervisor");
        mark_rejected_supervisor(&d, &bad);
        assert_eq!(
            std::fs::read_to_string(d.join(control::REJECTED_SUPERVISOR_FILE)).unwrap(),
            bad.to_str().unwrap()
        );
    }
}
