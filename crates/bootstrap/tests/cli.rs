use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn bootstrap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bootstrap"))
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("bootstrap-cli-{}-{tag}-{n}", std::process::id()))
}

#[cfg(unix)]
fn supervisor_script(tag: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("supervisor");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[cfg(unix)]
fn start_guardian(tag: &str, supervisor: &std::path::Path) -> std::process::Child {
    let state = temp_dir(tag);
    bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["--supervisor-config", "/unused/config.toml"])
        .args(["--supervisor", supervisor.to_str().unwrap()])
        .spawn()
        .unwrap()
}

#[cfg(unix)]
fn wait_for_exit(child: &mut std::process::Child, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[cfg(unix)]
fn wait_for_path(path: &std::path::Path, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn missing_path_value_is_a_usage_error() {
    let output = bootstrap().arg("--state-dir").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--state-dir needs a path"), "{stderr}");
    assert!(stderr.contains("usage: bootstrap"), "{stderr}");
}

#[test]
fn first_boot_without_a_supervisor_fails_closed() {
    let state = temp_dir("unseeded");
    let output = bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["--supervisor-config", "/unused/config.toml"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("fatal: no committed supervisor and no --supervisor to seed one"),
        "{stderr}"
    );
}

#[test]
fn help_prints_the_complete_operator_contract() {
    let output = bootstrap().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    for required in [
        "usage: bootstrap",
        "--state-dir",
        "--supervisor-config",
        "--supervisor",
        "--ready-timeout",
    ] {
        assert!(
            stderr.contains(required),
            "missing {required:?} in {stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn guardian_stays_alive_until_sigterm_then_exits_cleanly() {
    let ready = temp_dir("steady-ready");
    let supervisor = supervisor_script(
        "steady-supervisor",
        &format!(
            "trap 'exit 0' TERM INT\ntouch '{}'\nwhile :; do sleep 1; done",
            ready.display()
        ),
    );
    let mut child = start_guardian("steady-state", &supervisor);
    assert!(
        wait_for_path(&ready, std::time::Duration::from_secs(3)),
        "supervisor never reached readiness marker"
    );
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "guardian exited before shutdown"
    );

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    assert!(
        wait_for_exit(&mut child, std::time::Duration::from_secs(3)),
        "guardian ignored SIGTERM"
    );
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[cfg(unix)]
#[test]
fn supervisor_backoff_is_interrupted_by_shutdown() {
    let supervisor = supervisor_script("failed-supervisor", "exit 7");
    let mut child = start_guardian("backoff", &supervisor);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "guardian abandoned the crash loop"
    );

    let signalled = std::time::Instant::now();
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    assert!(
        wait_for_exit(&mut child, std::time::Duration::from_secs(1)),
        "shutdown waited for the full backoff"
    );
    assert!(signalled.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(child.wait().unwrap().code(), Some(0));
}
