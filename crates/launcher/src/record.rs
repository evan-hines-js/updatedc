//! The launcher's durable state, in tiny frozen text formats.
//!
//! The launcher keeps almost nothing, and interprets none of it. It moves one pointer —
//! which agent binary is committed (`desired-agent`) — forward on a successful handoff
//! and leaves it put on a failed one (that is the rollback). And it drops one dumb marker
//! for the agent to interpret on recovery: `rejected-agent`, the path of a candidate
//! that failed its readiness gate. It keeps no rejection set of its own.
//!
//! State-dir paths are required to be valid UTF-8 (checked at startup), so these files
//! are plain text.

use std::path::{Path, PathBuf};

/// The committed-agent pointer's filename and text format live in `control`: the agent
/// reads the same file (its staging GC must not delete the launcher's rollback target), so the
/// layout is a cross-process contract rather than launcher-private state.
const DESIRED_FILE: &str = control::DESIRED_AGENT_FILE;
const SEEDED_FILE: &str = "seeded-agent";

/// The committed agent binary path. `None` on first boot (the installer or the
/// `--agent` flag seeds it).
pub fn desired_agent(state_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    read_pointer(&state_dir.join(DESIRED_FILE))
}

pub fn set_desired_agent(state_dir: &Path, path: &Path) -> std::io::Result<()> {
    write_pointer(&state_dir.join(DESIRED_FILE), path)
}

/// The initial agent path recorded at first-boot seed. It lives *outside* the
/// content-addressed staging tree (the installer placed it), so validation of the committed
/// pointer trusts a non-staging path only when it matches this durable record — proving a prior
/// boot legitimately seeded it while `--agent` was present, rather than requiring the flag to
/// be re-passed on every restart (which would brick a node that never self-updated).
pub fn seeded_agent(state_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    read_pointer(&state_dir.join(SEEDED_FILE))
}

pub fn set_seeded_agent(state_dir: &Path, path: &Path) -> std::io::Result<()> {
    write_pointer(&state_dir.join(SEEDED_FILE), path)
}

fn read_pointer(path: &Path) -> std::io::Result<Option<PathBuf>> {
    control::read_agent_pointer(path)
}

/// Every file here is *managed* state, not a secret. A privately-ACLed write would discard the
/// state directory's intended inherited access and make launcher state inconsistent with the
/// rest of the runtime state.
fn write_pointer(path: &Path, target: &Path) -> std::io::Result<()> {
    let body = control::encode_agent_pointer(target)?;
    foundation::durable::atomic_write_managed(path, ".launcher-", body.as_bytes())
}

/// Note the path of a candidate agent that failed its readiness gate, for the agent to read
/// and reject on recovery. The launcher records the fact and forgets it — what to do about it
/// (skip that release forever) is the agent's policy.
pub fn mark_rejected_agent(state_dir: &Path, candidate: &Path) -> std::io::Result<()> {
    if let Some(s) = candidate.to_str() {
        // Durable + atomic so a crash mid-write can't leave a truncated path and a power
        // loss can't drop the rejection (which would let the bad candidate be re-staged).
        foundation::durable::atomic_write_managed(
            &state_dir.join(control::REJECTED_AGENT_FILE),
            ".launcher-",
            s.as_bytes(),
        )
    } else {
        Err(std::io::Error::other(
            "rejected agent path is not valid UTF-8",
        ))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let d = guard.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        (guard, d)
    }

    #[test]
    fn desired_agent_pointer_round_trips() {
        let (_tmp, d) = dir("desired");
        assert!(desired_agent(&d).unwrap().is_none());
        let p = d.join("agents/deadbeef/agent");
        set_desired_agent(&d, &p).unwrap();
        assert_eq!(desired_agent(&d).unwrap(), Some(p));
    }

    #[test]
    fn corrupt_pointer_is_an_error_not_first_boot() {
        let (_tmp, d) = dir("corrupt-desired");
        std::fs::write(d.join(DESIRED_FILE), b"not-a-pointer\n").unwrap();
        assert_eq!(
            desired_agent(&d).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn oversized_pointer_is_bounded_before_it_can_reach_the_launcher() {
        let (_tmp, d) = dir("oversized-desired");
        std::fs::write(
            d.join(DESIRED_FILE),
            vec![b'x'; control::MAX_AGENT_PATH_RECORD_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            desired_agent(&d).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn the_rejection_marker_is_written_for_the_agent_to_interpret() {
        let (_tmp, d) = dir("markers");
        let bad = d.join("agents/badc0de/agent");
        mark_rejected_agent(&d, &bad).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join(control::REJECTED_AGENT_FILE)).unwrap(),
            bad.to_str().unwrap()
        );
    }

    #[test]
    fn marker_write_failures_are_reported() {
        let (_tmp, d) = dir("marker-errors");
        std::fs::create_dir(d.join(control::REJECTED_AGENT_FILE)).unwrap();
        assert!(mark_rejected_agent(&d, Path::new("candidate")).is_err());
    }
}
