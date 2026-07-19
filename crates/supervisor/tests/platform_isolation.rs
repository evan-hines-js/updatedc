//! Guard: the supervisor must not re-inline process-tree containment primitives. Spawning
//! a child as a killable tree (Unix process group / Windows job object) is a platform
//! mechanism that belongs in `foundation::process`, not copied into the lifecycle-hook
//! runner. This test reads the source so the rule cannot erode unnoticed — the way
//! `bootstrap` guards its dependency isolation.
//!
//! The needles live here (a different file) than the source under inspection, so this
//! test's own literals never self-match.

use std::fs;
use std::path::Path;

/// Raw OS process-tree primitives that must only appear behind `foundation::process`.
const FORBIDDEN: &[&str] = &[
    "CreateJobObjectW",
    "AssignProcessToJobObject",
    "TerminateJobObject",
    "process_group(",
    "PR_SET_PDEATHSIG",
];

#[test]
fn lifecycle_runner_contains_no_inlined_process_tree_primitives() {
    let update_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/update.rs");
    let source = fs::read_to_string(&update_rs).expect("read supervisor/src/update.rs");
    for needle in FORBIDDEN {
        assert!(
            !source.contains(needle),
            "supervisor/src/update.rs reintroduced the platform primitive {needle:?}; \
             route process-tree containment through foundation::process instead"
        );
    }
    // Positive assertion: the runner does use the shared home. A drift that dropped the
    // dependency (e.g. someone re-inlined a std spawn) would fail here too.
    assert!(
        source.contains("foundation::process::ContainedChild"),
        "the lifecycle runner should spawn via foundation::process::ContainedChild"
    );
}
