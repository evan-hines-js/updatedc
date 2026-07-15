//! Guardian component label over the shared minimal logger.

pub fn info(msg: &str) {
    foundation::log::info("guardian", msg);
}
pub fn warn(msg: &str) {
    foundation::log::warn("guardian", msg);
}
pub fn error(msg: &str) {
    foundation::log::error("guardian", msg);
}
