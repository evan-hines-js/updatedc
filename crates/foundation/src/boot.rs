//! Operating-system boot identity, independent of process lifetime and wall-clock changes.
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn identity() -> io::Result<Vec<u8>> {
    let value = crate::file::read_bounded_regular_string(
        Path::new("/proc/sys/kernel/random/boot_id"),
        128,
        crate::file::FinalSymlink::Refuse,
    )?;
    uuid_identity(value.trim())
}

#[cfg(target_os = "macos")]
pub fn identity() -> io::Result<Vec<u8>> {
    let mut buffer = [0u8; 128];
    let mut length = buffer.len();
    // kern.bootsessionuuid is created by XNU for the boot session, unaffected by wall-clock
    // adjustments. See apple-oss-distributions/xnu, bsd/kern/kern_sysctl.c.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = buffer
        .get(..length)
        .ok_or_else(|| io::Error::other("oversized OS boot identity"))?;
    let value = std::str::from_utf8(value).map_err(io::Error::other)?;
    uuid_identity(value.trim_end_matches('\0'))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn uuid_identity(value: &str) -> io::Result<Vec<u8>> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OS boot UUID",
        ));
    }
    Ok(value.as_bytes().to_vec())
}

#[cfg(windows)]
pub fn identity() -> io::Result<Vec<u8>> {
    use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
    // SYSTEM_BOOT_ENVIRONMENT_INFORMATION (class 90): GUID, FIRMWARE_TYPE, aligned ULONGLONG.
    // Native layout: https://github.com/winsiderss/phnt/blob/master/ntexapi.h
    #[repr(C)]
    struct BootEnvironment {
        identifier: windows_sys::core::GUID,
        firmware_type: i32,
        flags: u64,
    }
    let mut info: BootEnvironment = unsafe { std::mem::zeroed() };
    let mut length = 0u32;
    let status = unsafe {
        NtQuerySystemInformation(
            90,
            (&mut info as *mut BootEnvironment).cast(),
            std::mem::size_of::<BootEnvironment>() as u32,
            &mut length,
        )
    };
    if status < 0 || length < 16 {
        return Err(io::Error::other(format!(
            "reading OS boot identity failed: NTSTATUS {status:#x}"
        )));
    }
    let id = info.identifier;
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&id.data1.to_le_bytes());
    bytes.extend_from_slice(&id.data2.to_le_bytes());
    bytes.extend_from_slice(&id.data3.to_le_bytes());
    bytes.extend_from_slice(&id.data4);
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other("empty OS boot identity"));
    }
    Ok(bytes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn identity() -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "OS boot identity is not supported",
    ))
}
