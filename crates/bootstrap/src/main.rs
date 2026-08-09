//! bootstrap — the installer-owned launcher: the one process that decides which agent
//! binary runs.
//!
//! It is the one program in the system that is meant never to change: a mechanism, not
//! a policy holder. It speaks no HTTP or TUF, selects no releases, parses no operator
//! config, and knows nothing of versions, hashes, health, or repository layout. Its whole job
//! is to run — and safely replace — a disposable agent that carries all of that policy.
//!
//! ```text
//!   init/systemd/SCM
//!     └── bootstrap (launcher)                     — this crate; frozen, zero project deps
//!           └── runs a disposable agent  ── over an inherited control channel
//!                 └── agent: TUF, update selection, hooks, health, rollback (all policy)
//! ```
//!
//! A self-updating agent must not be able to brick the node, and that is the whole reason
//! the launcher exists: a replacement agent is held to a readiness deadline and a
//! confirmation window, and one that fails either has its pointer reverted and its content
//! hash recorded rejected, so it is never retried. Workload processes belong to the release's
//! own hooks; the launcher has no means to touch them and no knowledge that they exist.
//! The operator's init system owns the launcher's own restarts.

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
    if let Err(e) = guardian::run(&cfg) {
        log::error(&format!("fatal: {e}"));
        std::process::exit(1);
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
    // The launcher stores content-addressed agent paths under the state dir, so it
    // must be a UTF-8 path (its frozen pointer files are text).
    if state_dir.to_str().is_none() {
        return Err("--state-dir must be a valid UTF-8 path".into());
    }
    // The config has one canonical location; passing it is for a non-standard layout only.
    let supervisor_config =
        supervisor_config.unwrap_or_else(|| PathBuf::from(control::DEFAULT_BOOTSTRAP_CONFIG));

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
        "bootstrap — the launcher: which agent binary runs\n\n\
         usage: bootstrap --state-dir <dir> [--supervisor-config <path.toml>] \\\n\
         \x20                [--supervisor <path>] [--ready-timeout <secs>]\n\
         \x20                [--confirm-timeout <secs>] [--stop-grace <secs>]\n\n\
         --state-dir          where the launcher keeps its agent pointers\n\
         --supervisor-config  operator config, passed verbatim to each agent;\n\
         \x20                    defaults to the canonical bootstrap.toml location, so\n\
         \x20                    pass it only for a non-standard layout\n\
         --supervisor         initial agent binary (first boot only; seeds the pointer)\n\
         --ready-timeout      how long a replacement agent has to prove ready (default 45s)\n\
         --confirm-timeout    stability window before committing a replacement (default 30s)\n\
         --stop-grace         graceful agent-stop deadline before a hard kill (default 10s)"
    );
}

#[cfg(test)]
mod dependency_isolation {
    //! The launcher's isolation is load-bearing: it must depend only on the frozen
    //! `control` protocol crate and platform binding crates — never on the churning
    //! tower or any behavioral third-party crate. This test reads the manifest so the
    //! rule cannot erode unnoticed.

    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// Frozen protocol and mechanism crates plus platform bindings. Both project crates
    /// are dependency-isolated and contain no tower policy or behavioral dependencies.
    const ALLOWED: &[&str] = &["control", "foundation", "libc", "windows-sys"];

    #[test]
    fn only_platform_binding_crates_are_allowed() {
        // `[dev-dependencies]` is not read: it is compiled only into this crate's own test
        // binaries and never links into the shipped launcher. That, and every other question of
        // what a manifest makes a crate ship, is answered in one place for all three crates that
        // enforce a dependency rule.
        for name in foundation::manifest::shipped_dependency_names(MANIFEST) {
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
            "the launcher must never depend on `updated` (which changes constantly)"
        );
    }
}
