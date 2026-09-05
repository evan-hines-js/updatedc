#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Entry point of the signed lifecycle-provider fixture for the operator demo.
//!
//! The fixture itself lives in [`reconciler`]. It owns the release's workload process — it
//! `setsid`s the workload out of the hook's contained tree, signals it on the next release, and
//! reads the process state back out of `/proc` on the Linux nodes the demo deploys to — so it
//! exists only for unix. That is a property of the *fixture*, not of the tower: keeping the unix
//! implementation behind `cfg(unix)` is what lets `cargo test --workspace --all-targets` compile
//! this workspace member on Windows too, instead of failing the whole build on a demo artifact no
//! Windows node ever runs. `/proc` is narrower than unix, so where it is absent the fixture's
//! liveness question answers "cannot tell" rather than "gone" and every caller treats that as
//! still-running; nothing here mistakes an unobservable workload for a stopped one.

#[cfg(unix)]
mod reconciler;

#[cfg(unix)]
fn main() {
    reconciler::run();
}

/// A non-unix build produces a binary that refuses to run rather than one that pretends to
/// reconcile: the agent invokes a reconciler expecting it to own a workload, and a stub that
/// exited 0 would report a deployment that never happened.
#[cfg(not(unix))]
fn main() {
    eprintln!(
        "demo-reconciler: this demo deployment fixture manages its workload through unix process \
         primitives and has no meaning on this platform"
    );
    std::process::exit(1);
}
