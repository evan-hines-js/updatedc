//! Exercise native commands and durable replay decisions through the distributed executable.
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    root: tempfile::TempDir,
    state: PathBuf,
    payload: PathBuf,
}
impl Fixture {
    fn new(replay: Value, recovery: Value) -> Self {
        let root = tempfile::tempdir().unwrap();
        let paths = updated::config::Paths::resolve(root.path(), root.path());
        let state = paths.reconciler_state_dir("app");
        let payload = root.path().join("versions/4.0.0-payload");
        for path in [
            &state,
            &payload,
            &root.path().join("outputs"),
            &root.path().join("inputs"),
        ] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(payload.join(".updated-execution.json"), json!({"schema":1,
            "deploy":procedure("fixture_deploy"), "health":procedure("fixture_health"), "replay":replay, "recovery":recovery}).to_string()).unwrap();
        Self {
            root,
            state,
            payload,
        }
    }
    fn command(&self, operation: &str, attempt: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_updated-agent"));
        command.env(
            updated_contracts::helper::EXECUTABLE_ENV,
            env!("CARGO_BIN_EXE_updated-agent"),
        );
        command.arg(operation).env(updated_contracts::helper::CONTEXT_ENV, json!({
            "protocol":"2","operation":operation,"attemptId":attempt,"reason":if updated_contracts::reconciler::attempt::is_reserved(attempt) {"restart"} else {"update"},
            "installRoot":self.root.path(),"stateDir":self.state,"payloadRoot":self.payload,"payloadVersion":"4.0.0",
            "inputDir":self.root.path().join("inputs"),"outputDir":self.root.path().join("outputs"),"resultFile":self.root.path().join("result.json")}).to_string());
        command
    }
    fn call(&self, operation: &str, attempt: &str) -> (bool, Value) {
        let _ = std::fs::remove_file(self.root.path().join("result.json"));
        let outputs = self.root.path().join("outputs");
        std::fs::remove_dir_all(&outputs).unwrap();
        std::fs::create_dir(&outputs).unwrap();
        let output = self.command(operation, attempt).output().unwrap();
        let result = std::fs::read(self.root.path().join("result.json"))
            .ok()
            .map(|s| serde_json::from_slice(&s).unwrap())
            .unwrap_or(Value::Null);
        if !output.status.success() {
            eprintln!(
                "adapter stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        (output.status.success(), result)
    }
    fn receipt(&self, operation: &str) -> PathBuf {
        self.state
            .join("commands")
            .join(updated::command_adapter::receipt_id(&self.payload).unwrap())
            .join(format!("{operation}.json"))
    }
    fn seed(&self, phase: &str) {
        let path = self.receipt("converge");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json!({"definition":updated_contracts::digest::sha256_bytes(&std::fs::read(self.payload.join(".updated-execution.json")).unwrap()),
            "inputsSha256":updated_contracts::digest::sha256_bytes(br#"{"files":{}}"#),"attempt":TOKEN,"transaction":TOKEN,"phase":phase,"message":"interrupted","exitCode":null}).to_string()).unwrap();
    }
    fn hold(&self, operation: &str, attempt: &str) {
        updated::command_adapter::write_attention(
            self.root.path(),
            &updated_contracts::attention::Attention {
                product: "app".into(),
                receipt: updated::command_adapter::receipt_id(&self.payload).unwrap(),
                operation: if operation == "rollback" {
                    updated_contracts::reconciler::MutationOperation::Rollback
                } else {
                    updated_contracts::reconciler::MutationOperation::Converge
                },
                attempt: attempt.into(),
                version: "4.0.0".into(),
                message: "decision required".into(),
            },
        )
        .unwrap();
    }
}
fn procedure(name: &str) -> Value {
    json!({"argv":[std::env::current_exe().unwrap(),"--exact",name,"--nocapture"],"timeoutSeconds":1})
}
fn recovery() -> Value {
    json!({"policy":"command","command":procedure("fixture_recover"),"replay":{"policy":"safe"}})
}
fn count(path: &Path) -> usize {
    std::fs::read_to_string(path).unwrap_or_default().len()
}
fn append(path: &Path) {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(b"x")
        .unwrap();
}

#[test]
fn clean_install_replay_and_health_drift_use_actual_state() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    let (_, first) = f.call("converge", TOKEN);
    assert_eq!(first["changed"], true);
    let (_, repeat) = f.call("converge", TOKEN);
    assert_eq!(repeat["changed"], false);
    assert_eq!(count(&f.state.join("deploy-count")), 1);
    std::fs::write(f.state.join("actual"), "drift").unwrap();
    let (_, repair) = f.call("converge", "converge");
    assert_eq!(repair["changed"], true);
    assert_eq!(
        std::fs::read_to_string(f.state.join("actual")).unwrap(),
        "v4"
    );
}
#[test]
fn changed_inputs_run_deploy_even_when_the_health_command_still_passes() {
    let f = Fixture::new(json!({"policy":"manual"}), recovery());
    assert_eq!(f.call("converge", TOKEN).1["status"], "succeeded");
    std::fs::write(
        f.root.path().join("inputs/config"),
        "new assigned configuration",
    )
    .unwrap();
    assert_eq!(f.call("converge", "converge").1["changed"], true);
    assert_eq!(f.call("converge", "converge").1["changed"], false);
    assert_eq!(count(&f.state.join("deploy-count")), 2);
}
#[test]
fn changed_inputs_cannot_disguise_uncertain_prior_work_as_a_completed_check() {
    let f = Fixture::new(
        json!({"policy":"check","command":procedure("fixture_check")}),
        recovery(),
    );
    f.seed("running");
    std::fs::write(f.state.join("check"), "0").unwrap();
    std::fs::write(f.root.path().join("inputs/config"), "changed").unwrap();
    assert_eq!(f.call("converge", TOKEN).1["status"], "needs-attention");
    assert_eq!(count(&f.state.join("deploy-count")), 0);
}

#[test]
fn killed_deployment_is_durable_and_manual_replay_refuses_even_a_new_attempt() {
    let f = Fixture::new(json!({"policy":"manual"}), recovery());
    std::fs::write(f.state.join("stall"), "yes").unwrap();
    let mut child =
        foundation::process::ContainedChild::spawn(f.command("converge", TOKEN)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f.state.join("actual").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    child.stop(Duration::ZERO);
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(f.receipt("converge")).unwrap()).unwrap();
    assert_eq!(receipt["phase"], "running");
    std::fs::remove_file(f.state.join("stall")).unwrap();
    let (ok, result) = f.call("converge", &"b".repeat(64));
    assert!(ok);
    assert_eq!(result["status"], "needs-attention");
    assert_eq!(count(&f.state.join("deploy-count")), 1);
}
#[test]
fn replay_check_proves_completion_or_safe_repetition_and_refuses_uncertainty() {
    for (check, expected, effects) in [
        ("0", "succeeded", 0),
        ("10", "succeeded", 1),
        ("20", "needs-attention", 0),
        ("stall", "needs-attention", 0),
    ] {
        let f = Fixture::new(
            json!({"policy":"check","command":procedure("fixture_check")}),
            recovery(),
        );
        f.seed("running");
        std::fs::write(f.state.join("check"), check).unwrap();
        let start = Instant::now();
        let (ok, result) = f.call("converge", TOKEN);
        assert!(ok);
        assert_eq!(result["status"], expected);
        assert_eq!(count(&f.state.join("deploy-count")), effects);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
#[test]
fn explicit_recovery_runs_once_and_predecessor_deploy_is_never_implicit() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    std::fs::write(f.state.join("fail-deploy"), "yes").unwrap();
    assert!(!f.call("converge", TOKEN).0);
    let rollback = format!("{TOKEN}r");
    for changed in [true, false] {
        let (ok, result) = f.call("rollback", &rollback);
        assert!(ok);
        assert_eq!(result["changed"], changed);
    }
    assert_eq!(count(&f.state.join("recovery-count")), 1);
    let (_, result) = f.call("converge", &rollback);
    assert_eq!(result["status"], "succeeded");
    // Restoring execution evidence is separate from readiness. The platform's bounded health
    // gate observes the unhealthy predecessor; no one-shot probe may create a permanent hold.
    assert!(!f.call("healthcheck", &rollback).0); // health expects v4, recovery restores v3
    assert!(updated::command_adapter::read_attention(f.root.path())
        .unwrap()
        .is_none());
    assert_eq!(count(&f.state.join("deploy-count")), 1);
}
#[test]
fn routine_repair_preserves_the_original_transaction_for_recovery() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    assert!(f.call("converge", TOKEN).0);
    std::fs::write(f.state.join("actual"), "drift").unwrap();
    assert!(f.call("converge", "boot").0);
    assert_eq!(count(&f.state.join("deploy-count")), 2);
    assert!(f.call("rollback", &format!("{TOKEN}r")).0);
    assert_eq!(count(&f.state.join("recovery-count")), 1);
    assert_eq!(
        std::fs::read_to_string(f.state.join("actual")).unwrap(),
        "v3"
    );
}

#[test]
fn failed_recovery_holds_and_operator_can_authorize_a_retry() {
    let f = Fixture::new(json!({"policy":"manual"}), recovery());
    f.seed("running");
    std::fs::write(f.state.join("fail-recovery"), "yes").unwrap();
    let rollback = format!("{TOKEN}r");
    let (_, result) = f.call("rollback", &rollback);
    assert_eq!(result["status"], "needs-attention");
    f.hold("rollback", &rollback);
    let paths = updated::config::Paths::resolve(f.root.path(), f.root.path());
    let lock = paths.lock_installation().unwrap();
    assert_eq!(
        updated::command_adapter::resolve(f.root.path(), "retry")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(lock);
    updated::command_adapter::resolve(f.root.path(), "retry").unwrap();
    // Simulate death after recording the decision but before removing the platform hold.
    f.hold("rollback", &rollback);
    updated::command_adapter::resolve(f.root.path(), "retry").unwrap();
    assert!(updated::command_adapter::read_attention(f.root.path())
        .unwrap()
        .is_none());
    std::fs::remove_file(f.state.join("fail-recovery")).unwrap();
    assert_eq!(f.call("rollback", &rollback).1["status"], "succeeded");
}
#[test]
fn manual_recovery_can_be_verified_without_executing_a_command() {
    let f = Fixture::new(json!({"policy":"manual"}), json!({"policy":"manual"}));
    f.seed("running");
    assert_eq!(f.call("converge", TOKEN).1["status"], "needs-attention");
    f.hold("converge", TOKEN);
    updated::command_adapter::resolve(f.root.path(), "recovered").unwrap();
    f.hold("converge", TOKEN); // same operator decision is crash-replay safe
    updated::command_adapter::resolve(f.root.path(), "recovered").unwrap();
    assert_eq!(
        f.call("rollback", &format!("{TOKEN}r")).1["status"],
        "succeeded"
    );
    assert_eq!(count(&f.state.join("deploy-count")), 0);
}
#[test]
fn contention_returns_retry_without_blocking_health_or_other_applications() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    std::fs::write(f.state.join("actual"), "v4").unwrap();
    let _lock = updated::lock::InstanceLock::acquire(&f.state.join("commands/.lock")).unwrap();
    let start = Instant::now();
    assert_eq!(f.call("converge", TOKEN).1["status"], "retry");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(f.call("healthcheck", TOKEN).0);
    assert!(f.call("inspect", "fingerprint").0);
    let other = Fixture::new(json!({"policy":"safe"}), recovery());
    assert_eq!(other.call("converge", TOKEN).1["status"], "succeeded");
}
#[test]
fn deadlines_release_locks_and_invalid_policy_cannot_start_commands() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    std::fs::write(f.state.join("stall"), "yes").unwrap();
    let start = Instant::now();
    assert!(!f.call("converge", TOKEN).0);
    assert!(start.elapsed() < Duration::from_secs(5));
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(f.receipt("converge")).unwrap()).unwrap();
    assert_eq!(receipt["message"], "command deadline exceeded");
    assert!(updated::lock::InstanceLock::acquire(&f.state.join("commands/.lock")).is_ok());
    let invalid = Fixture::new(json!({"policy":"probably-safe"}), recovery());
    assert!(!invalid.call("converge", TOKEN).0);
    assert!(!invalid.state.join("actual").exists());
}
#[test]
fn successful_helper_outputs_and_reboot_survive_completion_replay() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    std::fs::write(f.state.join("rich-result"), "yes").unwrap();
    for changed in [true, false] {
        let (ok, result) = f.call("converge", TOKEN);
        assert!(ok);
        assert_eq!(result["status"], "succeeded");
        assert_eq!(result["changed"], changed);
        assert_eq!(result["hostAction"], "reboot");
        assert_eq!(
            std::fs::read_to_string(f.root.path().join("outputs/endpoint")).unwrap(),
            "ready"
        );
    }
    assert_eq!(count(&f.state.join("deploy-count")), 1);
    let mut receipt: Value =
        serde_json::from_slice(&std::fs::read(f.receipt("converge")).unwrap()).unwrap();
    receipt["completion"]["boot_id"] = json!("0".repeat(64));
    std::fs::write(f.receipt("converge"), receipt.to_string()).unwrap();
    assert_eq!(f.call("converge", "boot").1["hostAction"], "none");
}
#[test]
fn malformed_completion_cannot_be_replayed_or_attested_as_ready() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    assert!(f.call("converge", TOKEN).0);
    let mut receipt: Value =
        serde_json::from_slice(&std::fs::read(f.receipt("converge")).unwrap()).unwrap();
    receipt["completion"]["result"] =
        json!({"schema":1,"status":"retry","retryAfterSeconds":1,"message":null});
    std::fs::write(f.receipt("converge"), receipt.to_string()).unwrap();
    assert!(!f.call("converge", TOKEN).0);
    assert_eq!(count(&f.state.join("deploy-count")), 1);
}
#[test]
fn an_explicit_retry_is_honored_even_with_manual_replay_policy() {
    let f = Fixture::new(json!({"policy":"manual"}), recovery());
    std::fs::write(f.state.join("retry-once"), "yes").unwrap();
    assert_eq!(f.call("converge", TOKEN).1["status"], "retry");
    assert_eq!(f.call("converge", TOKEN).1["status"], "succeeded");
    assert_eq!(count(&f.state.join("deploy-count")), 2);
}
#[test]
fn migration_step_checks_receive_observation_context() {
    let f = Fixture::new(json!({"policy":"safe"}), recovery());
    std::fs::write(f.state.join("step-check"), "yes").unwrap();
    assert_eq!(f.call("converge", TOKEN).1["status"], "succeeded");
    assert!(!f.state.join("forbidden").exists());
}
#[test]
fn fixture_step_check() {
    let Some(state) = std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from) else {
        return;
    };
    denied_probe_mutation(&state);
    std::process::exit(0);
}
#[test]
fn nested_health_and_replay_checks_cannot_use_mutation_helpers() {
    let f = Fixture::new(
        json!({"policy":"check","command":procedure("fixture_check")}),
        recovery(),
    );
    std::fs::write(f.state.join("probe-mutation"), "yes").unwrap();
    f.seed("running");
    assert_eq!(f.call("converge", TOKEN).1["status"], "succeeded");
    assert_eq!(f.call("converge", TOKEN).1["status"], "succeeded");
    assert!(!f.state.join("forbidden").exists());
}
fn helper(request: Value) -> bool {
    use std::io::Write;
    let mut child =
        Command::new(std::env::var_os(updated_contracts::helper::EXECUTABLE_ENV).unwrap())
            .arg(updated_contracts::helper::SUBCOMMAND)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    child.wait().unwrap().success()
}
fn denied_probe_mutation(state: &Path) {
    assert!(!helper(
        json!({"api":1,"command":"file","path":state.join("forbidden"),"content":"bad"})
    ));
}

#[test]
fn fixture_deploy() {
    let Some(state) = std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from) else {
        return;
    };
    append(&state.join("deploy-count"));
    std::fs::write(state.join("actual"), "v4").unwrap();
    if state.join("stall").exists() {
        std::thread::sleep(Duration::from_secs(30));
    }
    if state.join("step-check").exists() {
        let command = vec![
            std::env::current_exe().unwrap().display().to_string(),
            "--exact".into(),
            "fixture_step_check".into(),
            "--nocapture".into(),
        ];
        assert!(helper(
            json!({"api":1,"command":"sequence","resource":"db","timeoutSeconds":1,"steps":[{"id":"migration","definitionSha256":"a".repeat(64),"check":command,"apply":command,"timeoutSeconds":1}]})
        ));
    }
    if state.join("rich-result").exists() {
        assert!(helper(
            json!({"api":1,"command":"succeed","changed":true,"reboot":true,"outputs":{"endpoint":"ready"}})
        ));
    }
    if state.join("retry-once").exists() && count(&state.join("deploy-count")) == 1 {
        assert!(helper(json!({"api":1,"command":"retry","afterSeconds":1})));
    }
    std::process::exit(if state.join("fail-deploy").exists() {
        7
    } else {
        0
    });
}
#[test]
fn fixture_health() {
    let Some(state) = std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from) else {
        return;
    };
    if state.join("probe-mutation").exists() {
        denied_probe_mutation(&state);
    }
    std::process::exit(
        if matches!(
            std::fs::read_to_string(state.join("actual")).as_deref(),
            Ok("v4")
        ) {
            0
        } else {
            1
        },
    );
}
#[test]
fn fixture_check() {
    let Some(state) = std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from) else {
        return;
    };
    if state.join("probe-mutation").exists() {
        denied_probe_mutation(&state);
        std::process::exit(10);
    }
    let check = std::fs::read_to_string(state.join("check")).unwrap();
    if check == "stall" {
        std::thread::sleep(Duration::from_secs(30));
    }
    std::process::exit(check.parse().unwrap());
}
#[test]
fn fixture_recover() {
    let Some(state) = std::env::var_os("UPDATED_STATE_DIR").map(PathBuf::from) else {
        return;
    };
    append(&state.join("recovery-count"));
    if state.join("fail-recovery").exists() {
        std::process::exit(8);
    }
    std::fs::write(state.join("actual"), "v3").unwrap();
    std::process::exit(0);
}
