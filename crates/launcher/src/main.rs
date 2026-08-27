#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Cargo builds the ordinary binary as well as its test harness under llvm-cov. Only the latter
// contains the `cfg(test)` modules that use this feature.
#![cfg_attr(all(coverage_nightly, not(test)), allow(unused_features))]

//! updated-launcher — the installer-owned launcher: the one process that decides which
//! agent binary runs.
//!
//! It is the one program in the system that is meant never to change: a mechanism, not
//! a policy holder. It speaks no HTTP or TUF, selects no releases, parses no operator
//! config, and knows nothing of versions, hashes, health, or repository layout. Its whole job
//! is to run — and safely replace — a disposable agent that carries all of that policy.
//!
//! ```text
//!   init/systemd/SCM
//!     └── updated-launcher                        — this crate; frozen, zero project deps
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

mod agent;
mod launcher;
mod log;
mod rand;
mod record;
mod sys;

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("updated-launcher: {e}\n");
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = launcher::run(&cfg) {
        log::error(&format!("fatal: {e}"));
        std::process::exit(1);
    }
}

fn parse_args() -> Result<launcher::Config, String> {
    let mut state_dir: Option<PathBuf> = None;
    let mut config: Option<PathBuf> = None;
    let mut initial_agent: Option<PathBuf> = None;
    let mut ready_timeout = Duration::from_secs(45);
    let mut confirm_timeout = Duration::from_secs(30);
    let mut stop_grace = Duration::from_secs(10);

    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let flag = flag.to_str().ok_or("arguments must be valid UTF-8")?;
        match flag {
            "--state-dir" => state_dir = Some(next_path(&mut args, flag)?),
            "--config" => config = Some(next_path(&mut args, flag)?),
            "--agent" => initial_agent = Some(next_path(&mut args, flag)?),
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
    let config = config.unwrap_or_else(|| PathBuf::from(control::DEFAULT_CONFIG));

    Ok(launcher::Config {
        state_dir,
        config,
        initial_agent,
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
        "updated-launcher — which agent binary runs\n\n\
         usage: updated-launcher --state-dir <dir> [--config <path.toml>] \\\n\
         \x20                       [--agent <path>] [--ready-timeout <secs>]\n\
         \x20                       [--confirm-timeout <secs>] [--stop-grace <secs>]\n\n\
         --state-dir          where the launcher keeps its agent pointers\n\
         --config             operator config, passed verbatim to each agent;\n\
         \x20                    defaults to the canonical config.toml location, so\n\
         \x20                    pass it only for a non-standard layout\n\
         --agent              initial agent binary (first boot only; seeds the pointer)\n\
         --ready-timeout      how long a replacement agent has to prove ready (default 45s)\n\
         --confirm-timeout    stability window before committing a replacement (default 30s)\n\
         --stop-grace         graceful agent-stop deadline before a hard kill (default 10s)"
    );
}

/// Every flag the launcher accepts, as one list. `parse_args` matches exactly these and `usage`
/// documents exactly these, and the checked-in launch sites below are scanned against them — so a
/// flag deleted from the parser fails `cargo test` rather than crash-looping a pod.
#[cfg(test)]
const ACCEPTED_FLAGS: &[&str] = &[
    "--state-dir",
    "--config",
    "--agent",
    "--ready-timeout",
    "--confirm-timeout",
    "--stop-grace",
    "--help",
];

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod launch_sites {
    //! A launcher command line is duplicated as untyped text across shipped assets — a shell
    //! wrapper, Kubernetes manifests, an init unit, the README. Nothing else type-checks them, so a
    //! flag the parser no longer accepts survives right up until a node refuses to start. This
    //! scans them against the parser's own accepted set.

    use super::ACCEPTED_FLAGS;

    const SITES: &[(&str, &str)] = &[
        (
            "crates/updatec/e2e/agent.sh",
            include_str!("../../../crates/updatec/e2e/agent.sh"),
        ),
        (
            "scripts/kind-updatec-e2e.sh",
            include_str!("../../../scripts/kind-updatec-e2e.sh"),
        ),
        ("README.md", include_str!("../../../README.md")),
        (
            "deploy/systemd/updated-agent.service",
            include_str!("../../../deploy/systemd/updated-agent.service"),
        ),
        // These two files are the ONLY launcher command lines shipped for a node. The Ansible role
        // installs the package (which ships the unit above), and `install.sh` places whichever of
        // these two the release archive carries — none of them re-spell the invocation, so there is
        // nothing else here to scan.
        (
            "deploy/launchd/dev.updated.agent.plist",
            include_str!("../../../deploy/launchd/dev.updated.agent.plist"),
        ),
    ];

    /// Every `--flag` token on a line, with the punctuation shell, YAML and XML wrap them in
    /// stripped.
    fn flags(line: &str) -> Vec<&str> {
        line.split(|c: char| {
            c.is_whitespace() || matches!(c, ',' | '[' | ']' | '"' | '\'' | '<' | '>')
        })
        .filter(|token| token.starts_with("--") && token.len() > 2)
        .collect()
    }

    /// The launcher invocations in one asset: maximal runs of consecutive flag-bearing lines, kept
    /// only when the run names `--state-dir` — the one flag the launcher requires, so it marks a
    /// launcher command line and nothing else. A plist spells one argument per element, so its
    /// whole `ProgramArguments` array counts as a single invocation.
    fn invocations(path: &str, text: &str) -> Vec<Vec<String>> {
        if path.ends_with(".plist") {
            let all: Vec<String> = text.lines().flat_map(flags).map(str::to_owned).collect();
            return if all.iter().any(|f| f == "--state-dir") {
                vec![all]
            } else {
                Vec::new()
            };
        }
        // Markdown prose legitimately names launcher and reconciler flags next to one another.
        // Only fenced examples that actually invoke the launcher are launch sites; treating every
        // consecutive flag-bearing prose line as argv makes an unrelated layout comment such as
        // "the reconciler's --output-dir" look like a launcher option.
        if path.ends_with(".md") {
            let mut found = Vec::new();
            let mut block = String::new();
            let mut in_fence = false;
            for line in text.lines() {
                if line.trim_start().starts_with("```") {
                    if in_fence && block.contains("updated-launcher") {
                        let invocation: Vec<String> =
                            block.lines().flat_map(flags).map(str::to_owned).collect();
                        if invocation.iter().any(|flag| flag == "--state-dir") {
                            found.push(invocation);
                        }
                    }
                    block.clear();
                    in_fence = !in_fence;
                } else if in_fence {
                    block.push_str(line);
                    block.push('\n');
                }
            }
            return found;
        }
        let mut found = Vec::new();
        let mut run: Vec<String> = Vec::new();
        for line in text.lines() {
            let line_flags = flags(line);
            if line_flags.is_empty() {
                if run.iter().any(|f| f == "--state-dir") {
                    found.push(std::mem::take(&mut run));
                }
                run.clear();
                continue;
            }
            run.extend(line_flags.into_iter().map(str::to_owned));
        }
        if run.iter().any(|f| f == "--state-dir") {
            found.push(run);
        }
        found
    }

    #[test]
    fn every_shipped_launcher_invocation_uses_flags_the_parser_accepts() {
        let mut checked = 0;
        for (path, text) in SITES {
            for invocation in invocations(path, text) {
                checked += 1;
                for flag in invocation {
                    assert!(
                        ACCEPTED_FLAGS.contains(&flag.as_str()),
                        "{path} passes {flag}, which the launcher does not accept"
                    );
                }
            }
        }
        assert!(
            checked >= SITES.len(),
            "the scan found only {checked} launcher invocations; the extraction has stopped seeing them"
        );
    }

    #[test]
    fn the_accepted_set_is_exactly_what_the_parser_matches_and_usage_documents() {
        const SOURCE: &str = include_str!("main.rs");
        let parser = SOURCE
            .split_once("fn parse_args()")
            .expect("the parser")
            .1
            .split_once("fn next_path")
            .expect("the parser body")
            .0;
        let usage = SOURCE.split_once("fn usage()").expect("the usage text").1;
        for flag in ACCEPTED_FLAGS {
            assert!(
                parser.contains(&format!("\"{flag}\"")),
                "{flag} is advertised as accepted but the parser has no arm for it"
            );
            assert!(
                usage.contains(flag),
                "{flag} is accepted but undocumented in usage"
            );
        }
        for token in parser
            .split(|c: char| c.is_whitespace() || matches!(c, '"' | '|' | '=' | '>'))
            .filter(|t| t.starts_with("--") && t.len() > 2)
        {
            assert!(
                ACCEPTED_FLAGS.contains(&token),
                "the parser accepts {token}, which the checked set does not know about"
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
                "launcher must not depend on {name:?}; only platform binding crates \
                 ({ALLOWED:?}) are permitted, never a project or behavioral crate"
            );
        }
    }

    #[test]
    fn never_depends_on_the_tower() {
        for name in foundation::manifest::shipped_dependency_names(MANIFEST) {
            assert!(
                !name.starts_with("updated"),
                "the launcher must never depend on {name:?} (the tower changes constantly)"
            );
        }
    }
}
