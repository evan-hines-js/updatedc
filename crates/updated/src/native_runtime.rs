//! The agent executable and its exact native runtime dependencies form one installable unit.
use std::{io, path::Path};

include!(concat!(env!("OUT_DIR"), "/native_runtime.rs"));

/// Install dependencies before publishing the executable that loads them. Called at startup or
/// during packaging, never by a health probe. Static builds have no companion libraries.
pub fn install(source: &Path, target: &Path) -> io::Result<()> {
    let directory = foundation::durable::parent_dir(target);
    std::fs::create_dir_all(directory)?;
    for (name, bytes) in LIBRARIES {
        foundation::durable::atomic_write(&directory.join(name), ".native-runtime-", bytes)?;
    }
    foundation::durable::install_executable(target, source)
}

/// Distribution staging uses the same native dependency set as the pinned helper.
pub fn dispatch() -> Option<std::process::ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("stage-runtime")) {
        return None;
    }
    let result = (|| {
        let directory = args
            .next()
            .ok_or_else(|| io::Error::other("stage-runtime needs an output directory"))?;
        if args.next().is_some() {
            return Err(io::Error::other("unexpected stage-runtime argument"));
        }
        let source = std::env::current_exe()?;
        let name = if cfg!(windows) {
            "updated-agent.exe"
        } else {
            "updated-agent"
        };
        install(&source, &Path::new(&directory).join(name))
    })();
    Some(match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("staging agent runtime: {error}");
            std::process::ExitCode::FAILURE
        }
    })
}
