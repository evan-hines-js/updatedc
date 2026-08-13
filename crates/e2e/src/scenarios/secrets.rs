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

/// Assigned secrets are delivered to the RECONCILER, not to a process the agent owns: every hook
/// invocation carries the resolved values in its otherwise-cleared environment, and the entrypoint
/// puts them wherever its environment wants them (here, into the workload it starts). A rotation is
/// therefore an `apply --reason restart` and nothing else — the agent has no process to
/// reconfigure — and no value ever reaches disk.
pub(crate) fn assigned_secret_lifecycle(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:23180", "127.0.0.1:23181");
    let dir = ctx.work.join("assigned-secret-lifecycle");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
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
    let node = Node::new(ctx, &dir, srv, "app")
        .secret(ENVIRONMENT, "production-database", "password")
        .workload(svc)
        .check_interval("1s")
        .health_grace("1s");
    let mut command = node.clone().launcher()?;
    command.env(ENVIRONMENT, "ambient-value-must-not-reach-the-hook");
    let process = Service::spawn("assigned-secrets", &command);
    let fixture_root = fixture::root(&dir);

    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some(first_secret.as_str())
    }) {
        return fail(format!(
            "the initial assigned secret never reached the hook's environment:\n{}",
            process.captured_log()
        ));
    }
    let first_pid = fixture::workload_pid(&dir).ok_or("the reconciler recorded no workload PID")?;
    // The hook's own record of what it was handed: the NAME was present on every invocation. The
    // value is never written down, by the fixture or by anything else.
    let converges: Vec<_> = fixture::operations(&fixture_root)
        .into_iter()
        .filter(|invocation| invocation.operation == "apply")
        .collect();
    if converges.is_empty()
        || !converges
            .iter()
            .all(|invocation| invocation.has_environment(ENVIRONMENT))
    {
        return fail("a converge ran without the assigned secret in its environment");
    }

    write_bundle(&dir, "malformed-rotation", serde_json::json!({}))?;
    if !process.wait_for_log(
        "assigned secrets could not be reconciled; keeping the running application",
        EVENT_TIMEOUT,
    ) || http_text(&format!("http://{svc}/test-secret")).as_deref()
        != Some(first_secret.as_str())
        || fixture::workload_pid(&dir) != Some(first_pid)
    {
        return fail(format!(
            "a malformed rotation disturbed the running workload:\n{}",
            process.captured_log()
        ));
    }

    // Deliberately reuse the old generation. The agent must compare actual values and still
    // re-converge; generation is opaque metadata, not a security decision.
    let before_rotation = fixture::operations(&fixture_root).len();
    write_bundle(
        &dir,
        "generation-one",
        serde_json::json!({ENVIRONMENT: second_secret}),
    )?;
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some(second_secret.as_str())
            && fixture::workload_pid(&dir) != Some(first_pid)
    }) {
        return fail(format!(
            "the rotation did not reach the hook, which restarts the workload on a changed environment:\n{}",
            process.captured_log()
        ));
    }
    // The one mechanism a rotation has: `apply --reason restart`.
    let rotation = fixture::operations(&fixture_root);
    if !rotation
        .iter()
        .skip(before_rotation)
        .any(|invocation| invocation.operation == "apply" && invocation.reason == "restart")
    {
        return fail("the rotation did not converge through apply --reason restart");
    }

    let runtime_path = dir.join("assignment-runtime.json");
    let mut runtime: updated_contracts::assignment::ManagedRuntime =
        serde_json::from_slice(&std::fs::read(&runtime_path).map_err(str_err)?)
            .map_err(|error| error.to_string())?;
    runtime.secrets.clear();
    std::fs::write(
        &runtime_path,
        serde_json::to_vec(&runtime).map_err(|error| error.to_string())?,
    )
    .map_err(str_err)?;
    republish_assignment(&node, "secrets-removed")?;
    if !wait_until(EVENT_TIMEOUT, || {
        http_text(&format!("http://{svc}/test-secret")).as_deref() == Some("<missing>")
    }) {
        return fail(format!(
            "the removed assignment retained the secret in the hook's environment:\n{}",
            process.captured_log()
        ));
    }
    // Everything the reconciler is invoked with FROM HERE carries no secret. The window is opened
    // by the observation above — the workload the hook restarted no longer has the value — not by
    // the republish, because an invocation already in flight when the assignment changed was
    // correctly handed the environment that was assigned when it started.
    let removed_at = fixture::operations(&fixture_root).len();
    let clean = wait_until(EVENT_TIMEOUT, || {
        let later = fixture::operations(&fixture_root);
        later.len() > removed_at
            && later
                .iter()
                .skip(removed_at)
                .all(|invocation| !invocation.has_environment(ENVIRONMENT))
    });
    if !clean {
        return fail("a hook still received the removed secret's environment entry");
    }

    let install = dir.join("install");
    if contains_bytes(&install, first_secret.as_bytes())
        || contains_bytes(&install, second_secret.as_bytes())
        || contains_bytes(&fixture_root, first_secret.as_bytes())
        || contains_bytes(&fixture_root, second_secret.as_bytes())
    {
        return fail("secret bytes were persisted under the node install root or the hook's state");
    }
    let log = process.captured_log();
    if log.contains(&first_secret) || log.contains(&second_secret) {
        return fail("secret bytes appeared in the node's logs");
    }
    drop(process);
    ok("assigned secrets reached every hook invocation, rotated by apply --reason restart, were removed, and never touched disk");
    Ok(())
}

/// A bundle that does not carry every assigned secret must stop the converge before it starts. A
/// hook invoked with a partial environment would be indistinguishable, to the release, from one
/// whose secrets were deliberately removed — so no hook runs at all.
pub(crate) fn missing_assigned_secret_blocks_the_converge(ctx: &Ctx) -> R {
    let (srv, svc) = ("127.0.0.1:23182", "127.0.0.1:23183");
    let dir = ctx.work.join("missing-assigned-secret");
    std::fs::create_dir_all(&dir).map_err(str_err)?;
    let _workload = fixture::workload(&dir);
    ctx.init_repo(&dir)?;
    ctx.publish(&dir, "app", "1.0.0", &app_v(ctx, "1.0.0"))?;
    write_bundle(&dir, "incomplete", serde_json::json!({}))?;
    let _server = ctx.serve(&dir, srv)?;
    let mut command = Node::new(ctx, &dir, srv, "app")
        .secret(ENVIRONMENT, "production-database", "password")
        .workload(svc)
        .check_interval("1s")
        .launcher()?;
    let process = Proc::spawn("missing-assigned-secret", &mut command)?;
    let failed_closed = process.wait_for_log(
        "secret bundle that does not match the assignment",
        EVENT_TIMEOUT,
    ) && fixture::operations(&fixture::root(&dir)).is_empty()
        && http_text(&format!("http://{svc}/healthz")).is_none();
    let log = process.captured_log();
    drop(process);
    if !failed_closed {
        return fail(format!(
            "an incomplete bundle did not block the converge before any hook ran:\n{log}"
        ));
    }
    ok("an incomplete authorized bundle blocked the converge; no hook ever ran with partial secrets");
    Ok(())
}
