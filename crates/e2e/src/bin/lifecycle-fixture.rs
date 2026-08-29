//! Minimal executable adapter for the shared node-reconciler fixture.
//!
//! The full `e2e` binary also dispatches to this implementation, but packaging that scenario
//! runner as a frequently invoked Windows hook makes every lifecycle operation load and scan code
//! it can never execute. This binary keeps the implementation singular while leaving the driver
//! out of the provider artifact.

fn main() {
    if !e2e::fixture::dispatch_if_invoked() {
        eprintln!("lifecycle-fixture must be invoked through the reconciler protocol");
        std::process::exit(2);
    }
}
