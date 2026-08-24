//! One Rust version, declared once.
//!
//! `rust-toolchain.toml` is the declaration: `rustup` reads it for every local `cargo` invocation,
//! and the container builds install their toolchain through `rustup` precisely so the image tracks
//! it rather than naming a version of its own. The Dockerfiles used to say `FROM rust:1.95-bookworm`
//! — a second and third copy — and the workflows still pin the version explicitly, because the
//! toolchain action needs it before a checkout's `rust-toolchain.toml` can do anything.
//!
//! That leaves the workflow pins as the only remaining copies, so they are checked here rather than
//! trusted. Drift is not loud: a workflow pinned a minor version behind still passes, because the
//! action installs its version and then `cargo` silently downloads and uses the one the toolchain
//! file asks for. CI goes on being green while testing on a toolchain nobody chose, and paying for
//! a second toolchain download on every job.
//!
//! This lives in `foundation` because it is a property of the workspace, not of any one crate — the
//! same reason the lexical digest rules live here.

/// The channel `rust-toolchain.toml` pins, which is the one declaration.
fn declared_channel() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    for line in source.lines() {
        if let Some(value) = line.trim().strip_prefix("channel") {
            return value
                .trim_start_matches([' ', '='])
                .trim()
                .trim_matches('"')
                .to_string();
        }
    }
    panic!("rust-toolchain.toml declares no channel:\n{source}");
}

/// Every `toolchain:` pin in the GitHub workflows, with the file and line it came from.
fn workflow_pins() -> Vec<(String, usize, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut pins = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable workflow entry").path();
        if path
            .extension()
            .is_none_or(|ext| ext != "yml" && ext != "yaml")
        {
            continue;
        }
        let name = path
            .file_name()
            .expect("a workflow file name")
            .to_string_lossy()
            .into_owned();
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        for (index, line) in body.lines().enumerate() {
            // Both spellings the workflows use: a `with:` block key, and the inline
            // `with: {toolchain: X}` flow mapping.
            let Some(rest) = line.split("toolchain:").nth(1) else {
                continue;
            };
            let value = rest.trim().trim_end_matches('}').trim().trim_matches('"');
            if !value.is_empty() && value.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                pins.push((name.clone(), index + 1, value.to_string()));
            }
        }
    }
    pins
}

/// Every workflow pins the version the toolchain file declares.
#[test]
fn ci_pins_the_toolchain_the_workspace_declares() {
    let declared = declared_channel();
    let pins = workflow_pins();

    assert!(
        !pins.is_empty(),
        "found no toolchain pins in .github/workflows; this test is not checking anything (did \
         the workflows stop pinning, or change spelling?)"
    );

    for (file, line, pinned) in &pins {
        assert_eq!(
            pinned, &declared,
            "{file}:{line} pins Rust {pinned}, but rust-toolchain.toml declares {declared}. CI \
             would install {pinned} and then silently download {declared} on the first cargo \
             command, testing on a toolchain nobody chose."
        );
    }
}

/// No container build names a Rust version of its own.
///
/// The images install their toolchain with `rustup`, inside the workspace, so `rust-toolchain.toml`
/// selects it. Reintroducing a `FROM rust:<version>` base would restore the copy this removed —
/// and a stale one builds and ships perfectly happily.
#[test]
fn no_dockerfile_names_a_rust_version() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut checked = 0;
    for entry in std::fs::read_dir(&crates).expect("the crates directory is readable") {
        let dir = entry.expect("a readable crate entry").path();
        for file in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = file.path();
            if !path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("Dockerfile"))
            {
                continue;
            }
            checked += 1;
            let body = std::fs::read_to_string(&path).expect("a readable Dockerfile");
            for line in body.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with('#') {
                    continue; // prose may name the version it replaced
                }
                assert!(
                    !trimmed.contains("FROM rust:"),
                    "{} pins a Rust version in its base image; install the toolchain with rustup \
                     so rust-toolchain.toml stays the only declaration:\n  {line}",
                    path.display()
                );
            }
        }
    }
    assert!(checked > 0, "found no Dockerfiles to check");
}
