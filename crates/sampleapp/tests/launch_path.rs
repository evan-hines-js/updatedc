//! The launch path, end to end, at `cargo test` scope.
//!
//! A whole class of defect lives between "the provider resolved a release" and "the
//! application is running", and no unit test in `crates/updated` can see it: the
//! provider's own tests assert what is on disk, and the supervisor's assert what it
//! would exec. Neither runs a real program. That gap is exactly how the round-5
//! regression shipped — the launch `cwd` moved off the release tree to the writable
//! workspace, the workspace was empty, and `sampleapp` (which reads
//! `config/release.toml` relative to its `cwd`) died with `exit(2)` on every node.
//!
//! These tests close it the only way it can be closed: stage a bundle in the layout the
//! e2e fixtures ship (`bin/app` + `config/release.toml`, see
//! `crates/e2e/src/fixtures.rs`), install and resolve it through the real
//! [`updated::provider::BundleStore`], and launch this crate's real binary with the
//! resolved `program`/`cwd` and a cleared environment — exactly what
//! `crates/supervisor/src/app.rs` builds into its `CommandSpec`. The full e2e suite
//! proves the same thing more thoroughly, but it is a separate binary nobody runs by
//! reflex; this runs under `cargo test --workspace`.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use updated::bundle::{self, ExpectedBundle};
use updated::provider::BundleStore;

const PRODUCT: &str = "app";
const PLATFORM: &str = "test-platform";

/// A private root for one test, removed when the returned guard drops.
fn scratch() -> (tempfile::TempDir, PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let path = guard.path().to_path_buf();
    (guard, path)
}

/// Stage and install a release whose payload is the real `sampleapp` binary plus the
/// bundled config it reads by relative path — the e2e fixture layout.
fn install_release(
    root: &Path,
    version: &str,
) -> (BundleStore, bundle::ReleaseId, updated::provider::Resolved) {
    let source = root.join(format!("source-{version}"));
    std::fs::create_dir_all(source.join("bin")).unwrap();
    std::fs::create_dir_all(source.join("config")).unwrap();
    let entrypoint = format!("bin/app{}", std::env::consts::EXE_SUFFIX);
    std::fs::copy(env!("CARGO_BIN_EXE_sampleapp"), source.join(&entrypoint)).unwrap();
    std::fs::write(
        source.join("config/release.toml"),
        format!("version = \"{version}\"\n"),
    )
    .unwrap();

    let archive = root.join(format!("{version}.tar.zst"));
    bundle::create_bundle(&source, &archive, PRODUCT, version, PLATFORM, &entrypoint).unwrap();

    let store = BundleStore::new(
        root.join("versions"),
        root.join("staging"),
        root.join("work"),
    );
    let staged = store
        .install(
            &archive,
            &ExpectedBundle {
                product: PRODUCT,
                version,
                platform: PLATFORM,
            },
        )
        .unwrap();
    let resolved = store.resolve(&staged).unwrap();
    (store, staged, resolved)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Launch as `supervisor::app::app_spec` does: the resolved program, the resolved cwd,
/// and an explicitly constructed environment (nothing ambient crosses the boundary).
fn launch(resolved: &updated::provider::Resolved, port: u16) -> Child {
    Command::new(&resolved.program)
        .args(["--addr", &format!("127.0.0.1:{port}")])
        .current_dir(&resolved.cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Read the application's readiness line (it reports on stderr, as the e2e harness
/// reads it), or report why it never came. `sampleapp` exits 2 when it cannot read
/// `config/release.toml` from its working directory — the precise failure these tests
/// exist to catch — so an early EOF is diagnosed rather than merely timing out.
///
/// The read runs on its own thread behind a bounded `recv_timeout`, so a process that
/// comes up but never speaks fails the test instead of wedging `cargo test` forever.
fn await_ready_line(child: &mut Child) -> String {
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let line = BufReader::new(stderr).lines().map_while(Result::ok).next();
        let _ = tx.send(line);
    });
    let line = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(line) => line,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the application came up but never reported readiness within 30s");
        }
    };

    if let Some(line) = line {
        return line;
    }
    let status = child.wait().unwrap();
    assert_ne!(
        status.code(),
        Some(2),
        "the application could not read its own bundled config from the launch cwd \
         (exit 2). The workspace the provider hands back as `cwd` is not seeded with the \
         files the release manifest declares."
    );
    panic!("application produced no readiness line; status {status:?}");
}

/// The regression itself: a program launched the way the supervisor launches it finds
/// its own bundled configuration by relative path and comes up.
#[test]
fn the_real_application_starts_from_the_launch_cwd_the_provider_resolves() {
    let (_tmp, root) = scratch();
    let (store, id, resolved) = install_release(&root, "1.4.2");

    // The launch cwd must be the writable workspace, never the content-addressed tree:
    // any file the app writes into its cwd would otherwise be release drift.
    assert_ne!(resolved.cwd, store.location(&id));

    let port = free_port();
    let mut child = launch(&resolved, port);
    let line = await_ready_line(&mut child);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        line.contains("1.4.2") && line.contains("listening"),
        "the application did not report the version from its bundled config: {line:?}"
    );
}

/// The other half of the invariant. The workspace exists so an ordinary application can
/// write into its own working directory; doing so must not make the release it was
/// launched from fail verification on the next check tick (which would condemn a
/// perfectly good release and re-download it forever).
#[test]
fn what_the_application_writes_into_its_cwd_never_condemns_its_release() {
    let (_tmp, root) = scratch();
    let (_store, id, resolved) = install_release(&root, "2.0.0");

    let port = free_port();
    let mut child = launch(&resolved, port);
    let line = await_ready_line(&mut child);
    assert!(
        line.contains("2.0.0"),
        "unexpected readiness line: {line:?}"
    );

    // An ordinary application's own writes: a log, and a rewrite of a file it ships.
    std::fs::write(resolved.cwd.join("app.log"), b"started\n").unwrap();
    std::fs::write(
        resolved.cwd.join("config/release.toml"),
        "version = \"2.0.0\"\n# rewritten by the application\n",
    )
    .unwrap();

    let _ = child.kill();
    let _ = child.wait();

    bundle::verify_release(&root.join("versions"), &id)
        .expect("the application's writes to its workspace must not fail release verification");
}
