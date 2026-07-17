//! Dedicated same-PID reexec fixture. The implementation is shared with the ordinary
//! sample application; this separate executable makes the deployment contract explicit.

fn main() {
    sampleapp::run(true);
}
