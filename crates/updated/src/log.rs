//! Minimal transition-oriented logging shared by deployed components.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn info(component: &str, msg: &str) {
    emit(component, "INFO", msg);
}

pub fn warn(component: &str, msg: &str) {
    emit(component, "WARN", msg);
}

pub fn error(component: &str, msg: &str) {
    emit(component, "ERROR", msg);
}

fn emit(component: &str, level: &str, msg: &str) {
    // Init systems add the date; avoiding calendar formatting saves a dependency.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    eprintln!("{h:02}:{m:02}:{s:02} {level:<5} [{component}] {msg}");
}
