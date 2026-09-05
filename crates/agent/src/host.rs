use std::io;
use std::path::Path;
use std::process::Command;
use updated::helper::boot_identity;

/// Record the OS boot which still owes the requested reboot. Written before publishing hook
/// outputs or advancing a transaction, so every later failure retains the obligation.
pub(crate) fn record_reboot(path: &Path) -> io::Result<()> {
    record_reboot_at(path, &boot_identity()?)
}

fn record_reboot_at(path: &Path, boot: &str) -> io::Result<()> {
    if !updated_contracts::is_canonical_sha256(boot) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OS boot identity",
        ));
    }
    std::fs::create_dir_all(foundation::durable::parent_dir(path))?;
    foundation::durable::atomic_write(path, ".reboot-", boot.as_bytes())
}

/// Only a different OS boot satisfies the obligation. Service restarts, elapsed time, and a
/// successful shutdown-command exit do not. Read or removal errors keep recovery closed.
pub(crate) fn reboot_pending(path: &Path) -> io::Result<bool> {
    let Some(pending) = read_pending(path)? else {
        return Ok(false);
    };
    reconcile_reboot(path, &pending, &boot_identity()?)
}

fn read_pending(path: &Path) -> io::Result<Option<String>> {
    let boot = match foundation::file::read_bounded_regular_string(
        path,
        64,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(boot) => boot,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !updated_contracts::is_canonical_sha256(&boot) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pending reboot record",
        ));
    }
    Ok(Some(boot))
}

fn reconcile_reboot(path: &Path, pending: &str, current: &str) -> io::Result<bool> {
    if pending == current {
        return Ok(true);
    }
    foundation::durable::remove_path(path)?;
    Ok(false)
}

/// Ask the operating system to perform an orderly host reboot.
///
/// The command is fixed by the platform build, never supplied by a reconciler. A reconciler may
/// request the action, but cannot replace the privileged mechanism or its arguments.
pub(crate) fn request_reboot() -> io::Result<()> {
    bounded_reboot_command(reboot_command()?, std::time::Duration::from_secs(30))
}

fn bounded_reboot_command(command: Command, timeout: std::time::Duration) -> io::Result<()> {
    let status = foundation::process::run_to_exit(command, std::time::Instant::now() + timeout)?;
    if status == Some(0) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the operating-system reboot request failed with exit code {status:?}"
        )))
    }
}

#[cfg(target_os = "linux")]
fn reboot_command() -> io::Result<Command> {
    let mut command = Command::new("/usr/bin/systemctl");
    command.args(["reboot", "--no-wall"]);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn reboot_command() -> io::Result<Command> {
    let mut command = Command::new("/sbin/shutdown");
    command.args(["-r", "now"]);
    Ok(command)
}

#[cfg(windows)]
fn reboot_command() -> io::Result<Command> {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
    let mut command =
        Command::new(std::path::PathBuf::from(system_root).join("System32/shutdown.exe"));
    command.args([
        "/r",
        "/t",
        "5",
        "/d",
        "p:4:1",
        "/c",
        "updated reconciler requested a reboot",
    ]);
    Ok(command)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn reboot_command() -> io::Result<Command> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host reboot is not implemented on this operating system",
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn reboot_obligation_survives_restarts_and_only_an_os_boot_clears_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pending-reboot");
        let boot = "a".repeat(64);
        record_reboot_at(&path, &boot).unwrap();
        // A crash or failed command changes no durable evidence. Re-read on every restart.
        for _ in 0..3 {
            let persisted = read_pending(&path).unwrap().unwrap();
            assert!(reconcile_reboot(&path, &persisted, &boot).unwrap());
        }
        assert!(!reconcile_reboot(&path, &boot, &"b".repeat(64)).unwrap());
        assert!(read_pending(&path).unwrap().is_none());
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(reboot_pending(&path).is_err());
    }

    #[test]
    fn boot_identity_is_stable_across_reads() {
        let first = boot_identity().unwrap();
        assert!(updated_contracts::is_canonical_sha256(&first));
        assert_eq!(first, boot_identity().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn an_unresponsive_reboot_command_is_bounded() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30"]);
        let started = std::time::Instant::now();
        let error =
            bounded_reboot_command(command, std::time::Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn reboot_command_is_fixed_and_noninteractive() {
        let command = reboot_command().unwrap();
        assert!(!command.get_program().is_empty());
        assert!(command.get_args().next().is_some());
    }
}
