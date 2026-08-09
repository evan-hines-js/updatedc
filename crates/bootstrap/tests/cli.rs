use std::process::Command;

fn bootstrap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bootstrap"))
}

/// A unique, not-yet-created path inside a fresh scratch directory. The returned guard owns the
/// directory: hold it for as long as the path is in use (including by a spawned child), because
/// dropping it deletes the tree.
fn temp_dir(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let path = guard.path().join(tag);
    (guard, path)
}

#[cfg(unix)]
fn agent_script(tag: &str, body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let (guard, dir) = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("supervisor");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (guard, path)
}

#[cfg(unix)]
fn start_launcher(
    tag: &str,
    supervisor: &std::path::Path,
) -> (tempfile::TempDir, std::process::Child) {
    let (guard, state) = temp_dir(tag);
    let child = bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["--supervisor-config", "/unused/config.toml"])
        .args(["--supervisor", supervisor.to_str().unwrap()])
        .spawn()
        .unwrap();
    (guard, child)
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
    let (_tmp, state) = temp_dir("unseeded");
    let output = bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["--supervisor-config", "/unused/config.toml"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("fatal: no committed agent and no --supervisor to seed one"),
        "{stderr}"
    );
}

#[test]
fn the_config_path_defaults_so_a_standard_deployment_never_names_it() {
    // Omitting --supervisor-config must NOT be a usage error: a node's config has one canonical
    // location (`control::DEFAULT_BOOTSTRAP_CONFIG`) and every deployment adapter relies on that
    // default rather than restating a path. Reaching the *supervisor* fail-closed check (exit 1)
    // rather than an argument error (exit 2) is what proves the default was applied.
    let (_tmp, state) = temp_dir("default-config");
    let output = bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("fatal: no committed agent and no --supervisor to seed one"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("--supervisor-config is required"),
        "the config path must default, not be required: {stderr}"
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
fn the_launcher_stays_alive_until_sigterm_then_exits_cleanly() {
    let (_ready_tmp, ready) = temp_dir("steady-ready");
    let (_script_tmp, supervisor) = agent_script(
        "steady-supervisor",
        &format!(
            "trap 'exit 0' TERM INT\ntouch '{}'\nwhile :; do sleep 1; done",
            ready.display()
        ),
    );
    let (_state_tmp, mut child) = start_launcher("steady-state", &supervisor);
    assert!(
        wait_for_path(&ready, std::time::Duration::from_secs(3)),
        "the agent never reached readiness marker"
    );
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "the launcher exited before shutdown"
    );

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    assert!(
        wait_for_exit(&mut child, std::time::Duration::from_secs(3)),
        "the launcher ignored SIGTERM"
    );
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

/// Spawn a launcher with its stderr captured into a shared buffer, and its crash-loop backoff
/// widened so a shutdown deterministically lands inside the backoff sleep. A reader thread
/// drains the pipe so the child never blocks on a full stderr buffer.
#[cfg(unix)]
fn start_launcher_backoff_probe(
    tag: &str,
    supervisor: &std::path::Path,
) -> (
    tempfile::TempDir,
    std::process::Child,
    std::sync::Arc<std::sync::Mutex<String>>,
) {
    use std::io::Read;
    let (guard, state) = temp_dir(tag);
    let mut child = bootstrap()
        .args(["--state-dir", state.to_str().unwrap()])
        .args(["--supervisor-config", "/unused/config.toml"])
        .args(["--supervisor", supervisor.to_str().unwrap()])
        // Ten-minute base backoff (capped to the 5-minute ceiling): the launcher sits in the
        // sleep essentially the whole time, so the shutdown can never race the brief serve
        // window. The interruption fires within the 25ms poll regardless — nothing waits.
        .env("UPDATED_GUARDIAN_BACKOFF_BASE_MS", "600000")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut stderr = child.stderr.take().unwrap();
    let sink = log.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    (guard, child, log)
}

#[cfg(unix)]
fn wait_for_log(
    log: &std::sync::Mutex<String>,
    needle: &str,
    timeout: std::time::Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if log.lock().unwrap().contains(needle) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[cfg(unix)]
#[test]
fn agent_backoff_is_interrupted_by_shutdown() {
    // The agent exits at once, so the launcher is sitting in a (widened) relaunch backoff.
    // The proof that shutdown INTERRUPTS the sleep — rather than the sleep elapsing — is the
    // launcher's own durable log line, emitted only on the cut-short path. No wall-clock margin
    // is compared anywhere, so no amount of machine load can flake this: the timeouts below are
    // only anti-hang ceilings, orders of magnitude above the real (sub-second) latencies.
    let (_script_tmp, supervisor) = agent_script("failed-agent", "exit 7");
    let (_state_tmp, mut child, log) = start_launcher_backoff_probe("backoff", &supervisor);
    let ceiling = std::time::Duration::from_secs(30);

    assert!(
        wait_for_log(&log, "relaunching the agent in", ceiling),
        "the launcher never entered a relaunch backoff:\n{}",
        log.lock().unwrap()
    );

    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );

    assert!(
        wait_for_log(&log, "shutdown interrupted the relaunch backoff", ceiling),
        "shutdown did not interrupt the backoff:\n{}",
        log.lock().unwrap()
    );
    assert!(
        wait_for_exit(&mut child, ceiling),
        "the launcher did not exit after its backoff was interrupted"
    );
    assert_eq!(child.wait().unwrap().code(), Some(0));
}
