//! Compatibility facade for the shared dependency-isolated logger.

pub fn info(component: &str, msg: &str) {
    foundation::log::info(component, msg);
}

pub fn warn(component: &str, msg: &str) {
    foundation::log::warn(component, msg);
}

pub fn error(component: &str, msg: &str) {
    foundation::log::error(component, msg);
}
