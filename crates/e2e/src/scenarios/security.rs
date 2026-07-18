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
    if !wait_until(15, || tampered_root_converged(&tower.captured_log())) {
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

// ===========================================================================
// A tampered installer baseline is checked against the digest embedded by the
// installer before the process can execute, without repository availability.
// ===========================================================================
pub(crate) fn tampered_first_install_fails_closed(ctx: &Ctx) -> R {
    let srv = "127.0.0.1:21079";
    let dir = ctx.work.join("bad-baseline");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &v1)?;
    let _server = ctx.serve(&dir, srv)?;
    let cmd = Sup::new(
        ctx,
        &dir,
        srv,
        "app",
        appcmd(&app, &["--addr", "127.0.0.1:0"]),
    )
    .health_grace("1s")
    .guardian()?;
    let active = updated::bundle::read_active(&dir.join("install/active-release"))
        .map_err(str_err)?
        .ok_or("seed did not activate a release")?;
    let release_dir = dir.join("install/versions").join(active.directory_name());
    {
        use std::io::Write;
        make_writable(&release_dir.join("config/release.toml"))?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(release_dir.join("config/release.toml"))
            .and_then(|mut file| file.write_all(b"tampered = true\n"))
            .map_err(str_err)?;
    }
    let tower = Service::spawn("bad-baseline", &cmd);
    if !wait_until(10, || {
        tower.log_contains("release file type or size drifted")
    }) {
        return fail("no first-install trust failure was logged");
    }
    let log = tower.captured_log();
    if log.contains("started application pid") {
        return fail(format!(
            "tampered baseline reached application launch or committed state:\n{log}"
        ));
    }
    drop(tower);
    kill_stray(&dir.join("install"));
    ok("a tampered first-install binary was rejected before execution");
    Ok(())
}

// ===========================================================================
// A drifted on-disk binary is refused at startup (fail closed).
// ===========================================================================
pub(crate) fn drift_fail_closed(ctx: &Ctx) -> R {
    let dir = ctx.work.join("drift");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let v1 = app_v(ctx, "1.0.0");
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(&v1, &app).map_err(str_err)?;
    ctx.init_repo(&dir)?;

    // Build the command first (which seeds the immutable release), then tamper a
    // manifested file out of band.
    let cmd = Sup::new(
        ctx,
        &dir,
        "127.0.0.1:1",
        "app",
        appcmd(&app, &["--addr", "127.0.0.1:0"]),
    )
    .health_grace("1s")
    .guardian()?;
    let active = updated::bundle::read_active(&dir.join("install/active-release"))
        .map_err(str_err)?
        .ok_or("seed did not activate a release")?;
    let (_, installed_entrypoint) =
        updated::bundle::read_release(&dir.join("install/versions"), &active).map_err(str_err)?;
    {
        use std::io::Write;
        make_writable(&installed_entrypoint)?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&installed_entrypoint)
            .and_then(|mut f| f.write_all(b"TAMPER"))
            .map_err(str_err)?;
    }
    // Drift is checked at startup, before any TUF fetch; no server needed.
    let tower = Service::spawn("drift", &cmd);
    if !wait_until(10, || {
        tower.log_contains("release file type or size drifted")
    }) {
        return fail("no fail-closed drift message was logged");
    }
    let log = tower.captured_log();
    let state_unchanged = matches!(updated::state::read_installed(&dir.join("install/state/installed.json")), updated::state::Installed::Present(ref state) if state.release == active);
    if log.contains("started application pid") || !state_unchanged {
        return fail(format!(
            "drift rejection launched or mutated the managed installation:\n{log}"
        ));
    }
    drop(tower);
    ok("a drifted on-disk binary was refused (fail closed), never executed");
    Ok(())
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

// ===========================================================================
// 4. A second supervisor on the same install is refused by the instance lock.
// ===========================================================================
