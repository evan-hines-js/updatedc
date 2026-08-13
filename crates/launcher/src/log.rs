//! Launcher component label over the shared minimal logger.

pub fn info(msg: &str) {
    foundation::log::info("launcher", msg);
}
pub fn warn(msg: &str) {
    foundation::log::warn("launcher", msg);
}
pub fn error(msg: &str) {
    foundation::log::error("launcher", msg);
}
