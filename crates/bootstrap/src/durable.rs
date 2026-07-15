//! Guardian-specific names over the shared durable filesystem mechanisms.

use std::io;
use std::path::Path;

pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    foundation::durable::atomic_write(path, ".guardian-", data)
}
