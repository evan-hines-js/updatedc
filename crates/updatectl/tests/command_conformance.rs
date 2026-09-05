use serde_json::json;
use std::{path::PathBuf, process::Command};

#[test]
fn customer_payload_fixtures_run_through_the_real_conformance_harness() {
    let root = tempfile::tempdir().unwrap();
    let procedure = |name| json!({"argv":[std::env::current_exe().unwrap(),"--exact",name,"--nocapture"],"timeoutSeconds":5});
    for (name, expected) in [("candidate", "v2"), ("predecessor", "v1")] {
        let payload = root.path().join(name);
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("expected"), expected).unwrap();
        std::fs::write(payload.join(".updated-execution.json"), json!({"schema":1,
            "deploy":procedure("procedure_deploy"),"health":procedure("procedure_health"),"replay":{"policy":"safe"},
            "recovery":{"policy":"command","command":procedure("procedure_recover"),"replay":{"policy":"safe"}}}).to_string()).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_updatectl"))
        .arg("check")
        .arg(root.path().join("candidate"))
        .arg("--against")
        .arg(root.path().join("predecessor"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.path().join("candidate/commands").exists());
}
fn state() -> Option<PathBuf> {
    std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from)
}
#[test]
fn procedure_deploy() {
    let Some(state) = state() else {
        return;
    };
    std::fs::write(state.join("actual"), "v2").unwrap();
}
#[test]
fn procedure_health() {
    let Some(state) = state() else {
        return;
    };
    let expected = std::fs::read("expected").unwrap();
    std::process::exit(
        if std::fs::read(state.join("actual")).unwrap_or_default() == expected {
            0
        } else {
            1
        },
    );
}
#[test]
fn procedure_recover() {
    let Some(state) = state() else {
        return;
    };
    std::fs::write(state.join("actual"), "v1").unwrap();
}

#[test]
fn a_plain_entrypoint_needs_no_manifest_health_wrapper_or_published_runner() {
    let root = tempfile::tempdir().unwrap();
    let name = if cfg!(windows) {
        "program.exe"
    } else {
        "program"
    };
    for version in ["candidate", "previous"] {
        let payload = root.path().join(version);
        std::fs::create_dir(&payload).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), payload.join(name)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_updatectl"))
        .args(["check"])
        .arg(root.path().join("candidate"))
        .args([
            "--entrypoint",
            name,
            "--arg=--exact",
            "--arg=entrypoint_fixture",
            "--arg=--nocapture",
        ])
        .arg("--against")
        .arg(root.path().join("previous"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("manual recovery stops for attention"));
    assert!(!root
        .path()
        .join("candidate/.updated-execution.json")
        .exists());
    assert!(!root
        .path()
        .join("previous/.updated-execution.json")
        .exists());
}

#[test]
fn entrypoint_fixture() {
    let Some(state) = state() else {
        return;
    };
    assert!(!std::env::args().any(|arg| arg == "converge" || arg == "--attempt-id"));
    assert!(std::env::var_os("UPDATED_RECONCILER_HELPER").is_some());
    // Any duplicate execution fails the fixture, even if a platform result were to claim no change.
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(state.join("executed-once"))
        .unwrap();
    file.sync_all().unwrap();
}
