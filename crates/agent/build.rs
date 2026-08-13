// Bake the agent's version into the binary. Self-update *selection* is by content
// hash (a newer release whose bytes differ from ours), not by this version — but a
// baked version gives human-readable logs and, crucially, lets the e2e produce two
// distinguishable agent builds to publish as two releases. Defaults to the crate
// version; the e2e overrides it with AGENT_VERSION.
fn main() {
    let v = std::env::var("AGENT_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=AGENT_VERSION={v}");
    println!("cargo:rerun-if-env-changed=AGENT_VERSION");
    if std::env::var_os("AGENT_CHAOS_EXIT_AFTER_READY").is_some() {
        println!("cargo:rustc-cfg=agent_chaos_exit_after_ready");
    }
    println!("cargo:rustc-check-cfg=cfg(agent_chaos_exit_after_ready)");
    println!("cargo:rerun-if-env-changed=AGENT_CHAOS_EXIT_AFTER_READY");
}
