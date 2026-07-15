//! A three-line logger. The guardian cannot use the tower's `updated::log`, so it has
//! its own: a component prefix and a level on stderr, which the service manager
//! captures. Nothing more is warranted for a program this small.

pub fn info(msg: &str) {
    eprintln!("[guardian] {msg}");
}

pub fn warn(msg: &str) {
    eprintln!("[guardian] WARN {msg}");
}

pub fn error(msg: &str) {
    eprintln!("[guardian] ERROR {msg}");
}
