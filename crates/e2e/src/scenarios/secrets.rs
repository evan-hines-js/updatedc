use super::super::*;

const ENVIRONMENT: &str = "DATABASE_PASSWORD";

fn write_bundle(dir: &Path, generation: &str, values: serde_json::Value) -> R {
    let body = serde_json::json!({
        "deployment": "configured",
        "generation": generation,
        "values": values,
    });
    std::fs::write(
        dir.join("secret-bundle.json"),
        serde_json::to_vec(&body).map_err(|error| error.to_string())?,
    )
    .map_err(str_err)
}

fn contains_bytes(root: &Path, needle: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            contains_bytes(&path, needle)
        } else {
            std::fs::read(path)
                .ok()
                .is_some_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        }
    })
}

pub(crate) fn assigned_secret_lifecycle(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:23180", "127.0.0.1:23181");
    let dir = ctx.work.join("assigned-secret-lifecycle");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let first_secret = format!("alpha-{nonce}");
    let second_secret = format!("beta-{nonce}");
    write_bundle(
        &dir,
        "generation-one",
        serde_json::json!({ENVIRONMENT: first_secret}),
    )?;
    let _server = ctx.serve(&dir, srv)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    let sup = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .secret(ENVIRONMENT, "production-database", "password")
        .check_interval("1s")
        .health_grace("1s");
    let mut command = sup.clone().guardian()?;
    command.env(ENVIRONMENT, "ambient-value-must-not-reach-the-application");
    let process = Service::spawn("assigned-secrets", &command);

    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some(first_secret.as_str())
    }) {
        return fail(format!(
            "initial assigned secret was not injected:\n{}",
            process.captured_log()
        ));
    }
    let first_pid = http_text(&format!("http://{svc}/pid")).ok_or("missing initial app pid")?;

    write_bundle(&dir, "malformed-rotation", serde_json::json!({}))?;
    if !process.wait_for_log(
        "assigned secrets could not be reconciled; keeping the running application",
        EVENT_TIMEOUT,
    ) || http_text(&format!("http://{svc}/test-secret")).as_deref()
        != Some(first_secret.as_str())
        || http_text(&format!("http://{svc}/pid")).as_deref() != Some(first_pid.as_str())
    {
        return fail(format!(
            "a malformed rotation disturbed the running application:\n{}",
            process.captured_log()
        ));
    }

    // Deliberately reuse the old generation. The supervisor must compare actual values and still
    // restart; generation is opaque metadata, not a security decision.
    write_bundle(
        &dir,
        "generation-one",
        serde_json::json!({ENVIRONMENT: second_secret}),
    )?;
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some(second_secret.as_str())
            && http_text(&format!("http://{svc}/pid")).as_deref() != Some(first_pid.as_str())
    }) {
        return fail(format!(
            "secret rotation did not restart the app with the new value:\n{}",
            process.captured_log()
        ));
    }

    let runtime_path = dir.join("assignment-runtime.json");
    let mut runtime: updated::config::ManagedRuntime =
        serde_json::from_slice(&std::fs::read(&runtime_path).map_err(str_err)?)
            .map_err(|error| error.to_string())?;
    runtime.secrets.clear();
    std::fs::write(
        &runtime_path,
        serde_json::to_vec(&runtime).map_err(|error| error.to_string())?,
    )
    .map_err(str_err)?;
    republish_assignment(&sup, "secrets-removed")?;
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some("<missing>")
    }) {
        return fail(format!(
            "removed assignment retained the secret in the child environment:\n{}",
            process.captured_log()
        ));
    }

    let install = dir.join("install");
    if contains_bytes(&install, first_secret.as_bytes())
        || contains_bytes(&install, second_secret.as_bytes())
    {
        return fail("secret bytes were persisted under the node install root");
    }
    let log = process.captured_log();
    if log.contains(&first_secret) || log.contains(&second_secret) {
        return fail("secret bytes appeared in supervisor/application logs");
    }
    drop(process);
    kill_stray(&install);
    ok("secret injection, rotation restart, removal, and non-persistence all held");
    Ok(())
}

pub(crate) fn missing_assigned_secret_blocks_launch(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:23182", "127.0.0.1:23183");
    let dir = ctx.work.join("missing-assigned-secret");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    write_bundle(&dir, "incomplete", serde_json::json!({}))?;
    let _server = ctx.serve(&dir, srv)?;
    let app = dir.join(format!("app{}", ctx.exe));
    std::fs::copy(app_v(ctx, "1.0.0"), &app).map_err(str_err)?;
    let mut command = Sup::new(ctx, &dir, srv, "app", appcmd(&app, &["--addr", svc]))
        .secret(ENVIRONMENT, "production-database", "password")
        .check_interval("1s")
        .guardian()?;
    let process = Proc::spawn("missing-assigned-secret", &mut command)?;
    let failed_closed = process.wait_for_log(
        "secret bundle that does not match the assignment",
        EVENT_TIMEOUT,
    ) && http_text(&format!("http://{svc}/pid")).is_none();
    let log = process.captured_log();
    drop(process);
    kill_stray(&dir.join("install"));
    if !failed_closed {
        return fail(format!(
            "an incomplete bundle did not block application launch:\n{log}"
        ));
    }
    ok("an incomplete authorized bundle prevented application launch");
    Ok(())
}
