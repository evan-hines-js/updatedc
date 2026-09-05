//! Exercise the shipped binary, JSON interface, and native subprocesses on every supported OS.
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn context(root: &Path, operation: &str) -> Value {
    std::fs::create_dir_all(root.join("outputs")).unwrap();
    json!({"protocol":"2","operation":operation,"attemptId":if operation == "healthcheck" {"periodic"} else {"converge"},
        "reason":"restart","installRoot":root,"stateDir":root.join("state"),"payloadRoot":root.join("payload"),
        "payloadVersion":"1.0.0","inputDir":root.join("inputs"),"outputDir":root.join("outputs"),"resultFile":root.join("result.json")})
}

fn call(root: &Path, operation: &str, request: Value, fail_after_apply: bool) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_updated-agent"))
        .arg("reconciler-helper")
        .env(
            updated_contracts::helper::CONTEXT_ENV,
            context(root, operation).to_string(),
        )
        .env("UPDATED_TEST_STEP_DEST", root.join("effect"))
        .env(
            "UPDATED_TEST_FAIL_AFTER_APPLY",
            if fail_after_apply { "1" } else { "0" },
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let response = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={:?} stderr={:?}",
            output.stdout, output.stderr
        )
    });
    (output.status.success(), response)
}

fn step_request(resource: &str) -> Value {
    let executable = std::env::current_exe().unwrap();
    json!({"api":1,"command":"sequence","resource":resource,"timeoutSeconds":5,"steps":[{"id":"schema-2","definitionSha256":"a".repeat(64),
        "check":[executable,"--exact","step_fixture_check","--nocapture"],
        "apply":[executable,"--exact","step_fixture_apply","--nocapture"],"timeoutSeconds":5}]})
}

#[test]
fn capabilities_need_no_configuration_and_unknown_api_cannot_mutate() {
    let root = tempfile::tempdir().unwrap();
    let (ok, response) = call(
        root.path(),
        "converge",
        json!({"api":1,"command":"capabilities"}),
        false,
    );
    assert!(ok, "{response}");
    assert_eq!(response["value"]["apis"], json!([1]));
    let capabilities = response["value"]["capabilities"].as_array().unwrap();
    assert!(capabilities.contains(&json!("sequence")));
    assert!(!capabilities.contains(&json!("step")));
    let (ok, response) = call(
        root.path(),
        "converge",
        json!({"api":99,"command":"file","path":root.path().join("never"),"content":"secret"}),
        false,
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "unsupported");
    assert!(!root.path().join("never").exists());
}

#[test]
fn file_convergence_repairs_drift_and_observations_cannot_write() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("file with spaces");
    let request =
        json!({"api":1,"command":"file","path":path,"content":"quotes \" and Unicode λ\n"});
    for changed in [true, false] {
        let (ok, result) = call(root.path(), "converge", request.clone(), false);
        assert!(ok, "{result}");
        assert_eq!(result["value"]["changed"], changed);
    }
    std::fs::write(&path, "drift").unwrap();
    assert!(!call(root.path(), "healthcheck", request.clone(), false).0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "drift");
    assert_eq!(
        call(root.path(), "converge", request, false).1["value"]["changed"],
        true
    );
}

#[test]
fn results_and_complete_outputs_are_published_even_on_unchanged_replay() {
    let root = tempfile::tempdir().unwrap();
    for changed in [true, false] {
        let request = json!({"api":1,"command":"result","result":{"schema":1,"status":"succeeded","changed":changed,"hostAction":"none","message":null},"outputs":{"endpoint":"https://example.invalid/λ"}});
        let (ok, result) = call(root.path(), "converge", request, false);
        assert!(ok, "{result}");
        let document = std::fs::read(root.path().join("result.json")).unwrap();
        assert!(
            updated_contracts::reconciler::ResultDocument::from_bounded_json(&document).is_ok()
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("outputs/endpoint")).unwrap(),
            "https://example.invalid/λ"
        );
        std::fs::remove_file(root.path().join("outputs/endpoint")).unwrap();
        std::fs::remove_file(root.path().join("result.json")).unwrap();
    }
}

#[test]
fn interrupted_effect_is_inspected_before_replay_and_identity_reuse_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let request = step_request("database");
    assert!(!call(root.path(), "converge", request.clone(), true).0);
    assert_eq!(std::fs::read(root.path().join("effect")).unwrap(), b"done");
    let (ok, result) = call(root.path(), "converge", request.clone(), true);
    assert!(ok, "{result}");
    assert_eq!(result["value"]["changed"], false);
    let mut reused = request;
    reused["steps"][0]["definitionSha256"] = json!("b".repeat(64));
    assert!(!call(root.path(), "converge", reused, false).0);
}

#[test]
fn resource_contention_does_not_wait_or_block_an_independent_resource() {
    let root = tempfile::tempdir().unwrap();
    let _held = updated::lock::InstanceLock::acquire(
        &root.path().join("state/helper-steps/database/.lock"),
    )
    .unwrap();
    let start = Instant::now();
    let (ok, result) = call(root.path(), "converge", step_request("database"), false);
    assert!(!ok);
    assert_eq!(result["error"]["code"], "busy");
    assert!(start.elapsed() < Duration::from_secs(5));
    let (ok, result) = call(
        root.path(),
        "converge",
        step_request("another-database"),
        false,
    );
    assert!(ok, "{result}");
}

#[test]
fn helper_pin_survives_replacement_of_the_distributed_executable() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("agent");
    std::fs::write(&source, b"old executable").unwrap();
    let pinned = updated::helper::pin(&source, &root.path().join("pinned")).unwrap();
    std::fs::write(&source, b"new executable").unwrap();
    assert_eq!(std::fs::read(pinned).unwrap(), b"old executable");
}

#[test]
fn a_relocated_runtime_and_pinned_helper_need_no_loader_environment() {
    let root = tempfile::tempdir().unwrap();
    let packaged = root.path().join(if cfg!(windows) {
        "updated-agent.exe"
    } else {
        "updated-agent"
    });
    let mut stage = Command::new(env!("CARGO_BIN_EXE_updated-agent"));
    updated::reconciler::configure_environment(&mut stage);
    let result = stage
        .arg("stage-runtime")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let pinned = updated::helper::pin(&packaged, &root.path().join("pinned")).unwrap();
    for executable in [&packaged, &pinned] {
        if executable == &pinned {
            std::fs::remove_file(&packaged).unwrap();
            for (name, _) in updated::native_runtime::LIBRARIES {
                std::fs::remove_file(root.path().join(name)).unwrap();
            }
        }
        let mut command = Command::new(executable);
        updated::reconciler::configure_environment(&mut command);
        let mut child = command
            .arg("reconciler-helper")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"{\"api\":1,\"command\":\"capabilities\"}")
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let response: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(response["ok"], true);
    }
}

#[test]
fn step_fixture_check() {
    let Some(path) = std::env::var_os("UPDATED_TEST_STEP_DEST") else {
        return;
    };
    std::process::exit(match std::fs::read(path) {
        Ok(bytes) if bytes == b"done" => 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 10,
        _ => 20,
    });
}

#[test]
fn step_fixture_apply() {
    let Some(path) = std::env::var_os("UPDATED_TEST_STEP_DEST") else {
        return;
    };
    std::fs::write(path, b"done").unwrap();
    std::process::exit(
        if std::env::var("UPDATED_TEST_FAIL_AFTER_APPLY").as_deref() == Ok("1") {
            9
        } else {
            0
        },
    );
}

#[test]
fn malformed_requests_do_not_echo_secret_values_or_mutate() {
    let root = tempfile::tempdir().unwrap();
    let (ok, response) = call(
        root.path(),
        "converge",
        json!({"api":1,"command":"file","path":root.path().join("never"),"content":"secret","typo":"private credential"}),
        false,
    );
    assert!(!ok);
    assert!(!response.to_string().contains("private credential"));
    assert!(
        !call(
            root.path(),
            "converge",
            json!({"api":1,"command":"capabilities","typo":"x"}),
            false
        )
        .0
    );
    assert!(!root.path().join("never").exists());
}

#[test]
fn a_stalled_migration_is_bounded_and_releases_its_lock() {
    let root = tempfile::tempdir().unwrap();
    let mut request = step_request("database");
    request["steps"][0]["check"] = json!([
        std::env::current_exe().unwrap(),
        "--exact",
        "step_fixture_stalled",
        "--nocapture"
    ]);
    request["timeoutSeconds"] = json!(1);
    let start = Instant::now();
    let (ok, response) = call(root.path(), "converge", request, false);
    assert!(!ok);
    assert_eq!(response["error"]["code"], "timeout");
    assert!(start.elapsed() < Duration::from_secs(6));
    assert!(call(root.path(), "converge", step_request("database"), false).0);
}

#[test]
fn step_fixture_stalled() {
    if std::env::var_os("UPDATED_TEST_STEP_DEST").is_some() {
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn upgrade_sequence() -> Value {
    let steps: Vec<_> = (32..=35)
        .map(|minor| {
            let command = json!([
                std::env::current_exe().unwrap(),
                "--exact",
                format!("sequence_fixture_{minor}"),
                "--nocapture"
            ]);
            json!({"id":format!("k8s-1-{minor}"),"definitionSha256":format!("{minor:064x}"),
            "check":command,"apply":command,"timeoutSeconds":5})
        })
        .collect();
    json!({"api":1,"command":"sequence","resource":"cluster","timeoutSeconds":20,"steps":steps})
}

// These fixtures model application-owned compatibility and health checks. The platform sees only
// opaque commands. A real Kubernetes integration must also inspect and coordinate the whole cluster.
fn sequence_fixture(from: Option<u32>, to: u32) {
    let Some(path) = std::env::var_os("UPDATED_TEST_STEP_DEST").map(std::path::PathBuf::from)
    else {
        return;
    };
    let current = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text.parse::<u32>().unwrap()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("{error}"),
    };
    let observing = std::env::var("UPDATED_OPERATION").as_deref() == Ok("healthcheck");
    // Every check and apply, including later ones, must run while the same resource is locked.
    let lock = updated::lock::InstanceLock::acquire(
        &path
            .parent()
            .unwrap()
            .join("state/helper-steps/cluster/.lock"),
    );
    assert!(matches!(lock, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    if observing {
        std::process::exit(if current.is_some_and(|minor| (to..=35).contains(&minor)) {
            0
        } else if current == from {
            10
        } else {
            20
        });
    }
    assert_eq!(
        current, from,
        "application refuses a skipped minor or an install on existing state"
    );
    std::fs::write(&path, to.to_string()).unwrap();
    let mut history = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path.with_file_name("history"))
        .unwrap();
    writeln!(history, "{to}").unwrap();
    if to == 33 && path.with_file_name("pause-after-33").exists() {
        std::thread::sleep(Duration::from_secs(30));
    }
    std::process::exit(
        if to == 33 && std::env::var("UPDATED_TEST_FAIL_AFTER_APPLY").as_deref() == Ok("1") {
            9
        } else {
            0
        },
    );
}

#[test]
fn sequence_fixture_install() {
    sequence_fixture(None, 35);
}
#[test]
fn sequence_fixture_32() {
    sequence_fixture(Some(31), 32);
}
#[test]
fn sequence_fixture_33() {
    sequence_fixture(Some(32), 33);
}
#[test]
fn sequence_fixture_34() {
    sequence_fixture(Some(33), 34);
}
#[test]
fn sequence_fixture_35() {
    sequence_fixture(Some(34), 35);
}

#[test]
fn install_and_upgrade_can_use_distinct_paths_with_the_same_sequence_executor() {
    let fresh = tempfile::tempdir().unwrap();
    let command = json!([
        std::env::current_exe().unwrap(),
        "--exact",
        "sequence_fixture_install",
        "--nocapture"
    ]);
    let mut install = upgrade_sequence();
    install["steps"] = json!([{"id":"install-1-35","definitionSha256":"a".repeat(64),
        "check":command,"apply":command,"timeoutSeconds":5}]);
    let (ok, result) = call(fresh.path(), "converge", install, false);
    assert!(ok, "{result}");
    assert_eq!(
        std::fs::read_to_string(fresh.path().join("history")).unwrap(),
        "35\n"
    );

    let existing = tempfile::tempdir().unwrap();
    std::fs::write(existing.path().join("effect"), "31").unwrap();
    let (ok, result) = call(existing.path(), "converge", upgrade_sequence(), false);
    assert!(ok, "{result}");
    assert_eq!(result["value"], json!({"changed":true,"completed":4}));
    let history = existing.path().join("history");
    assert_eq!(
        std::fs::read_to_string(&history).unwrap(),
        "32\n33\n34\n35\n"
    );
    let (ok, result) = call(existing.path(), "converge", upgrade_sequence(), false);
    assert!(ok, "{result}");
    assert_eq!(result["value"]["changed"], false);
    assert_eq!(
        std::fs::read_to_string(history).unwrap(),
        "32\n33\n34\n35\n"
    );
}

#[test]
fn failed_sequence_stops_and_rechecks_destination_before_continuing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    let (ok, result) = call(root.path(), "converge", upgrade_sequence(), true);
    assert!(!ok);
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("k8s-1-33 (2/4)"));
    assert_eq!(
        std::fs::read_to_string(root.path().join("history")).unwrap(),
        "32\n33\n"
    );
    // The interrupted step took effect. Inspect it; do not execute it twice or trust its receipt.
    let (ok, result) = call(root.path(), "converge", upgrade_sequence(), true);
    assert!(ok, "{result}");
    assert_eq!(
        std::fs::read_to_string(root.path().join("history")).unwrap(),
        "32\n33\n34\n35\n"
    );
}

#[test]
fn killing_a_sequence_releases_its_lock_and_preserves_inspectable_progress() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    std::fs::write(root.path().join("pause-after-33"), "pause").unwrap();
    let request_path = root.path().join("sequence.json");
    std::fs::write(&request_path, upgrade_sequence().to_string()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_updated-agent"));
    command
        .arg("reconciler-helper")
        .env(
            updated_contracts::helper::CONTEXT_ENV,
            context(root.path(), "converge").to_string(),
        )
        .env("UPDATED_TEST_STEP_DEST", root.path().join("effect"))
        .stdin(Stdio::from(std::fs::File::open(request_path).unwrap()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = foundation::process::ContainedChild::spawn(command).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::read_to_string(root.path().join("history")).unwrap_or_default() != "32\n33\n" {
        assert!(
            Instant::now() < deadline,
            "sequence did not reach the interruption point"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    child.stop(Duration::ZERO);
    assert!(updated::lock::InstanceLock::acquire(
        &root.path().join("state/helper-steps/cluster/.lock")
    )
    .is_ok());
    assert!(!root
        .path()
        .join("state/helper-steps/cluster/k8s-1-34.json")
        .exists());
    std::fs::remove_file(root.path().join("pause-after-33")).unwrap();
    let (ok, result) = call(root.path(), "converge", upgrade_sequence(), false);
    assert!(ok, "{result}");
    assert_eq!(
        std::fs::read_to_string(root.path().join("history")).unwrap(),
        "32\n33\n34\n35\n"
    );
}

#[test]
fn a_bad_later_step_is_rejected_before_any_effect() {
    let mut cases = Vec::new();
    let mut invalid = upgrade_sequence();
    invalid["steps"][3]["apply"] = json!([]);
    cases.push(invalid);
    let mut duplicate = upgrade_sequence();
    duplicate["steps"][3]["id"] = duplicate["steps"][0]["id"].clone();
    cases.push(duplicate);
    let mut unknown = upgrade_sequence();
    unknown["steps"][3]["unexpected"] = json!(true);
    cases.push(unknown);
    let mut empty = upgrade_sequence();
    empty["steps"] = json!([]);
    cases.push(empty);
    let mut invalid_timeout = upgrade_sequence();
    invalid_timeout["steps"][3]["timeoutSeconds"] = json!(0);
    cases.push(invalid_timeout);
    let mut invalid_id = upgrade_sequence();
    invalid_id["steps"][3]["id"] = json!("../escape");
    cases.push(invalid_id);
    let mut excessive = upgrade_sequence();
    excessive["steps"] = json!((0..=updated_contracts::helper::MAX_SEQUENCE_STEPS)
        .map(|index| {
            let mut step = excessive["steps"][0].clone();
            step["id"] = json!(format!("step-{index}"));
            step
        })
        .collect::<Vec<_>>());
    cases.push(excessive);
    for request in cases {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("effect"), "31").unwrap();
        assert!(!call(root.path(), "converge", request, false).0);
        assert_eq!(
            std::fs::read_to_string(root.path().join("effect")).unwrap(),
            "31"
        );
        assert!(!root.path().join("history").exists());
    }
}

#[test]
fn a_conflicting_later_identity_is_rejected_before_any_effect() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    let directory = root.path().join("state/helper-steps/cluster");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("k8s-1-35.json"),
        json!({"definition_sha256":"b".repeat(64),"complete":true}).to_string(),
    )
    .unwrap();
    assert!(!call(root.path(), "converge", upgrade_sequence(), false).0);
    assert!(!root.path().join("history").exists());
}

#[test]
fn a_sequence_deadline_stops_later_steps_and_releases_the_resource() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    let mut request = upgrade_sequence();
    request["timeoutSeconds"] = json!(1);
    request["steps"][1]["check"] = json!([
        std::env::current_exe().unwrap(),
        "--exact",
        "step_fixture_stalled",
        "--nocapture"
    ]);
    let (ok, result) = call(root.path(), "converge", request, false);
    assert!(!ok);
    assert_eq!(result["error"]["code"], "timeout");
    assert_eq!(
        std::fs::read_to_string(root.path().join("history")).unwrap(),
        "32\n"
    );
    assert!(updated::lock::InstanceLock::acquire(
        &root.path().join("state/helper-steps/cluster/.lock")
    )
    .is_ok());
}

#[test]
fn application_preconditions_refuse_a_missing_upgrade_hop() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    let mut request = upgrade_sequence();
    request["steps"].as_array_mut().unwrap().remove(0);
    assert!(!call(root.path(), "converge", request, false).0);
    assert!(!root.path().join("history").exists());
}

#[test]
fn successful_apply_without_a_verified_postcondition_cannot_advance() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("effect"), "31").unwrap();
    let mut request = upgrade_sequence();
    // This subprocess succeeds without doing the transition. Its exit status is insufficient.
    request["steps"][0]["apply"] = json!([
        std::env::current_exe().unwrap(),
        "--exact",
        "sequence_fixture_noop",
        "--nocapture"
    ]);
    let (ok, result) = call(root.path(), "converge", request, false);
    assert!(!ok);
    assert!(result["error"]["message"]
        .as_str()
        .unwrap()
        .contains("postcondition was not verified"));
    assert!(!root.path().join("history").exists());
}

#[test]
fn sequence_fixture_noop() {}

#[test]
fn a_step_deadline_is_enforced_inside_a_longer_sequence_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut request = step_request("database");
    request["timeoutSeconds"] = json!(10);
    request["steps"][0]["timeoutSeconds"] = json!(1);
    request["steps"][0]["check"] = json!([
        std::env::current_exe().unwrap(),
        "--exact",
        "step_fixture_stalled",
        "--nocapture"
    ]);
    let start = Instant::now();
    let (ok, result) = call(root.path(), "converge", request, false);
    assert!(!ok);
    assert_eq!(result["error"]["code"], "timeout");
    assert!(start.elapsed() < Duration::from_secs(6));
    assert!(!root.path().join("effect").exists());
}
