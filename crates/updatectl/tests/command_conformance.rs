use std::{path::PathBuf, process::Command};

#[test]
fn customer_payload_fixtures_run_through_the_real_conformance_harness() {
    let root = tempfile::tempdir().unwrap();
    let (name, interpreter, script) = if cfg!(windows) {
        (
            "run.ps1",
            // Use the runner's current PowerShell runtime. Legacy Windows PowerShell startup
            // can exceed the agent's entire health budget before this script gets control.
            "pwsh",
            r#"$ErrorActionPreference = 'Stop'
$actual = Join-Path $env:UPDATED_STATE_DIR 'actual'
switch ($env:UPDATED_OPERATION) {
  'converge' { Set-Content -NoNewline -Path $actual -Value 'v2' }
  'rollback' { Set-Content -NoNewline -Path $actual -Value 'v1' }
  'healthcheck' { if ((Get-Content -Raw $actual) -ceq (Get-Content -Raw 'expected')) { exit 0 }; exit 1 }
  default { exit 1 }
}
"#,
        )
    } else {
        (
            "run.sh",
            "sh",
            r#"set -eu
case "$UPDATED_OPERATION" in
  converge) printf v2 > "$UPDATED_STATE_DIR/actual" ;;
  rollback) printf v1 > "$UPDATED_STATE_DIR/actual" ;;
  healthcheck) cmp -s "$UPDATED_STATE_DIR/actual" expected ;;
  *) exit 1 ;;
esac
"#,
        )
    };
    for (version, expected) in [("candidate", "v2"), ("predecessor", "v1")] {
        let payload = root.path().join(version);
        std::fs::create_dir(&payload).unwrap();
        std::fs::write(payload.join("expected"), expected).unwrap();
        std::fs::write(payload.join(name), script).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_updatectl"))
        .arg("check")
        .arg(root.path().join("candidate"))
        .arg("--against")
        .arg(root.path().join("predecessor"))
        .args([
            "--entrypoint",
            name,
            "--interpreter",
            interpreter,
            "--healthcheck",
            name,
            "--health-timeout-seconds",
            "20",
            "--recover",
            name,
            "--replay",
            "safe",
            "--recovery-replay",
            "safe",
        ])
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
