// Bake the supervisor's version into the binary. Self-update *selection* is by content
// hash (a newer release whose bytes differ from ours), not by this version — but a
// baked version gives human-readable logs and, crucially, lets the e2e produce two
// distinguishable supervisor builds to publish as two releases. Defaults to the crate
// version; the e2e overrides it with SUPERVISOR_VERSION.
fn main() {
    let v = std::env::var("SUPERVISOR_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=SUPERVISOR_VERSION={v}");
    println!("cargo:rerun-if-env-changed=SUPERVISOR_VERSION");
    if std::env::var_os("SUPERVISOR_CHAOS_EXIT_AFTER_READY").is_some() {
        println!("cargo:rustc-cfg=supervisor_chaos_exit_after_ready");
    }
    println!("cargo:rustc-check-cfg=cfg(supervisor_chaos_exit_after_ready)");
    println!("cargo:rerun-if-env-changed=SUPERVISOR_CHAOS_EXIT_AFTER_READY");
}
