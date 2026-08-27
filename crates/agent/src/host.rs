use std::io;
use std::process::Command;

/// Ask the operating system to perform an orderly host reboot.
///
/// The command is fixed by the platform build, never supplied by a reconciler. A reconciler may
/// request the action, but cannot replace the privileged mechanism or its arguments.
pub(crate) fn request_reboot() -> io::Result<()> {
    let mut command = reboot_command()?;
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the operating-system reboot request exited with {status}"
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
    fn reboot_command_is_fixed_and_noninteractive() {
        let command = reboot_command().unwrap();
        assert!(!command.get_program().is_empty());
        assert!(command.get_args().next().is_some());
    }
}
