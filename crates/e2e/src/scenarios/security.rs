use super::super::*;
pub(crate) fn tampered_root_fails_closed(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21088";
    let dir = ctx.work.join("badroot");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;

    let _server = ctx.serve(&dir, srv)?;
    // Publish the routing assignment before corrupting the installer-pinned root;
    // repository authoring itself correctly refuses to operate through a corrupt root.
    let root = ctx.root(&dir);
    let mut bytes = std::fs::read(&root).map_err(str_err)?;
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&root, &bytes).map_err(str_err)?;
    let cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(&app, &["--addr", "127.0.0.1:0"]),
    )
    .check_interval("1s")
    .health_grace("1s")
    .guardian()?;
    let tower = Service::spawn("bad-root", &cmd);
    // Wait for both independent outcomes. Do not match a generic word such as
    // "root": the scenario's own `badroot` path appears in the startup log and can
    // satisfy such a predicate before the application launch or TUF refresh occurs.
    if !wait_until(EVENT_TIMEOUT, || {
        tampered_root_converged(&tower.captured_log())
    }) {
        return fail(format!(
            "tampered root did not converge to a running baseline plus fail-closed TUF result:\n{}",
            tower.captured_log()
        ));
    }
    let log = tower.captured_log();
    if !log.contains("started application pid")
        || log.contains("applying update")
        || log.contains("upgraded to")
    {
        return fail(format!(
            "tampered trust root either blocked the installer baseline or authorized an update:\n{log}"
        ));
    }
    drop(tower);
    kill_stray(&app);
    ok("a tampered pinned root blocked updates while the verified installer baseline remained runnable");
    Ok(())
}

fn tampered_root_converged(log: &str) -> bool {
    log.contains("started application pid") && log.contains("TUF refresh failed a trust check")
}

#[cfg(test)]
mod tests {
    use super::tampered_root_converged;

    #[test]
    fn a_badroot_path_is_not_a_trust_failure() {
        let startup = r#"supervising "/tmp/e2e-work/badroot/app""#;
        assert!(!tampered_root_converged(startup));
        assert!(!tampered_root_converged(&format!(
            "{startup}\nstarted application pid 42"
        )));
        assert!(tampered_root_converged(&format!(
            "{startup}\nstarted application pid 42\nTUF refresh failed a trust check"
        )));
    }
}
