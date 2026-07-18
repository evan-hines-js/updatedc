//! bootstrap — the installer-owned root of the update tower and the permanent process
//! guardian that owns the managed application.
//!
//! It is the one program in the system that is meant never to change: a mechanism, not
//! a policy holder. It speaks no HTTP or TUF, selects no releases, parses no operator
//! config, and knows nothing of versions, hashes, health, or repository layout. Its whole job
//! is to own the application process across supervisor generations and to run — and
//! safely replace — a disposable supervisor that carries all of that policy.
//!
//! ```text
//!   init/systemd/SCM
//!     └── bootstrap (guardian)                     — this crate; frozen, zero project deps
//!           ├── owns the application  ── process group / Job Object containment
//!           └── runs a disposable supervisor  ── over an inherited control channel
//!                 └── supervisor: TUF, update selection, health, rollback (all policy)
//! ```
//!
//! Because the guardian never lets go of the application, a supervisor crash, restart,
//! or self-update never disturbs it. The application never outlives the guardian:
//! platform process containment tears it down if the guardian exits unexpectedly.
//! There is only ever one guardian, so there is never a second owner racing to launch
//! a duplicate.

mod app;
mod guardian;
mod log;
mod rand;
mod record;
mod supervisor;
mod sys;

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("bootstrap: {e}\n");
            usage();
            std::process::exit(2);
        }
    };
    // The guardian is transparent: it exits with the application's rolled-up exit code
    // (or 0 for a clean stop), so the init system sees the app's real fate.
    match guardian::run(&cfg) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            log::error(&format!("fatal: {e}"));
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<guardian::Config, String> {
    let mut state_dir: Option<PathBuf> = None;
    let mut supervisor_config: Option<PathBuf> = None;
    let mut initial_supervisor: Option<PathBuf> = None;
    let mut ready_timeout = Duration::from_secs(45);
    let mut confirm_timeout = Duration::from_secs(30);
    let mut stop_grace = Duration::from_secs(10);

    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let flag = flag.to_str().ok_or("arguments must be valid UTF-8")?;
        match flag {
            "--state-dir" => state_dir = Some(next_path(&mut args, flag)?),
            "--supervisor-config" => supervisor_config = Some(next_path(&mut args, flag)?),
            "--supervisor" => initial_supervisor = Some(next_path(&mut args, flag)?),
            "--ready-timeout" => ready_timeout = next_seconds(&mut args, flag)?,
            "--confirm-timeout" => confirm_timeout = next_seconds(&mut args, flag)?,
            "--stop-grace" => stop_grace = next_seconds(&mut args, flag)?,
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let state_dir = state_dir.ok_or("--state-dir is required")?;
    // The guardian stores content-addressed supervisor paths under the state dir, so it
    // must be a UTF-8 path (its frozen pointer files are text).
    if state_dir.to_str().is_none() {
        return Err("--state-dir must be a valid UTF-8 path".into());
    }
    let supervisor_config = supervisor_config.ok_or("--supervisor-config is required")?;

    Ok(guardian::Config {
        state_dir,
        supervisor_config,
        initial_supervisor,
        ready_timeout,
        confirm_timeout,
        stop_grace,
    })
}

fn next_path(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<PathBuf, String> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} needs a path"))
}

fn next_seconds(
    args: &mut impl Iterator<Item = std::ffi::OsString>,
    flag: &str,
) -> Result<Duration, String> {
    args.next()
        .and_then(|v| v.to_str().and_then(|s| s.parse::<u64>().ok()))
        .map(Duration::from_secs)
        .ok_or_else(|| format!("{flag} needs a whole number of seconds"))
}

fn usage() {
    eprintln!(
        "bootstrap — the update tower's root and the application's permanent guardian\n\n\
         usage: bootstrap --state-dir <dir> --supervisor-config <path.toml> \\\n\
         \x20                [--supervisor <path>] [--ready-timeout <secs>]\n\
         \x20                [--confirm-timeout <secs>] [--stop-grace <secs>]\n\n\
         --state-dir          where the guardian keeps ownership + supervisor pointers\n\
         --supervisor-config  operator config, passed verbatim to each supervisor\n\
         --supervisor         initial supervisor binary (first boot only; seeds the pointer)\n\
         --ready-timeout      how long a replacement supervisor has to prove ready (default 45s)\n\
         --confirm-timeout    stability window before committing a replacement (default 30s)\n\
         --stop-grace         graceful process-stop deadline before a hard kill (default 10s)"
    );
}

#[cfg(test)]
mod dependency_isolation {
    //! The guardian's isolation is load-bearing: it must depend only on the frozen
    //! `control` protocol crate and platform binding crates — never on the churning
    //! tower or any behavioral third-party crate. This test reads the manifest so the
    //! rule cannot erode unnoticed.

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Frozen protocol and mechanism crates plus platform bindings. Both project crates
    /// are dependency-isolated and contain no tower policy or behavioral dependencies.
    const ALLOWED: &[&str] = &["control", "foundation", "libc", "windows-sys"];

    #[test]
    fn only_platform_binding_crates_are_allowed() {
        let mut in_deps = false;
        for line in MANIFEST.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_deps = line.contains("dependencies");
                continue;
            }
            if !in_deps || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = line.split(['=', '.', ' ']).next().unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            assert!(
                ALLOWED.contains(&name),
                "bootstrap must not depend on {name:?}; only platform binding crates \
                 ({ALLOWED:?}) are permitted, never a project or behavioral crate"
            );
        }
    }

    #[test]
    fn never_depends_on_the_tower() {
        let code: String = MANIFEST
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("updated"),
            "the guardian must never depend on `updated` (which changes constantly)"
        );
    }
}
