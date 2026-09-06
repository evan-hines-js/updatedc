use crate::*;
use updated_contracts::releases::ReleaseGraph;

fn graph_at(dir: &Path, target: &str) -> R<ReleaseGraph> {
    let mut graph: ReleaseGraph =
        serde_json::from_slice(&std::fs::read(dir.join("application.json")).map_err(str_err)?)
            .map_err(str_err)?;
    for release in graph.releases.values_mut() {
        release.upgrade_from.clear();
        release.rollback_from.clear();
        release.installable = false;
    }
    for (to, from) in [(3, 1), (4, 2), (6, 3), (7, 3), (10, 6), (10, 7)] {
        graph
            .releases
            .get_mut(&format!("{to}.0.0"))
            .unwrap()
            .upgrade_from
            .insert(format!("{from}.0.0"));
    }
    for (to, from) in [(1, 3), (2, 4), (3, 6), (3, 7), (7, 10)] {
        graph
            .releases
            .get_mut(&format!("{to}.0.0"))
            .unwrap()
            .rollback_from
            .insert(format!("{from}.0.0"));
    }
    for version in ["1.0.0", "2.0.0"] {
        graph.releases.get_mut(version).unwrap().installable = true;
    }
    graph.target = target.into();
    graph.validate().map_err(str_err)?;
    Ok(graph)
}

fn assign_graph(ctx: &Ctx, dir: &Path, graph: &ReleaseGraph) -> R {
    graph.validate().map_err(str_err)?;
    std::fs::write(
        dir.join("application.json"),
        serde_json::to_vec(graph).map_err(str_err)?,
    )
    .map_err(str_err)?;
    let release = std::fs::read_to_string(dir.join("release-base-url")).map_err(str_err)?;
    publish_assignment(
        &ctx.server,
        dir,
        &format!("{release}metadata/"),
        &format!("{release}targets/"),
        &format!("route-{}", graph.target),
    )
}

fn confirmed(dir: &Path, version: &str) -> bool {
    matches!(updated::state::read_installed(&node_paths(dir).installed),
        updated::state::Installed::Present(state) if state.release.version == version && state.rollback_guard.is_none())
}

/// Real signed repositories, supervised agents, workload health, and persisted transactions.
/// The return route differs from the upgrade route and survives an agent restart between hops.
pub(crate) fn complex_release_graph_and_multihop_rollback(ctx: &Ctx) -> R {
    let root = ctx.work.join("release-graph-topology");
    let mut workloads = Vec::new();
    let mut servers = Vec::new();
    let mut nodes = Vec::new();
    for (index, name, initial) in [
        (0, "old", "1.0.0"),
        (1, "recent", "7.0.0"),
        (2, "stranded", "2.0.0"),
        (3, "fresh", "10.0.0"),
    ] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).map_err(str_err)?;
        workloads.push(fixture::workload(&dir));
        ctx.init_repo(&dir)?;
        for version in [1, 2, 3, 4, 6, 7, 10] {
            // The fixture executable is version-agnostic; the publisher signs each bundle's version.
            ctx.publish(&dir, "app", &format!("{version}.0.0"), &app_v(ctx, "1.0.0"))?;
        }
        let mut graph = graph_at(&dir, initial)?;
        if initial == "7.0.0" {
            graph.releases.get_mut(initial).unwrap().installable = true;
        }
        std::fs::write(
            dir.join("application.json"),
            serde_json::to_vec(&graph).map_err(str_err)?,
        )
        .map_err(str_err)?;
        let repository = format!("127.0.0.1:{}", 23970 + index * 2);
        let service = format!("127.0.0.1:{}", 23971 + index * 2);
        servers.push(ctx.serve(&dir, &repository)?);
        let command = Node::new(ctx, &dir, &repository, "app")
            .cold_install()
            .workload(&service)
            .check_interval("1s")
            .health_grace("2s")
            .health_successes(1)
            .confirmation_window("2s")
            .command()?;
        nodes.push((dir, service, initial, Service::spawn(name, &command)));
    }
    for (dir, address, initial, service) in &nodes {
        if !wait_for_version(address, initial, CONVERGE_TIMEOUT)
            || !wait_until(CONVERGE_TIMEOUT, || confirmed(dir, initial))
        {
            return fail(format!(
                "initial topology did not settle at {initial}:\n{}",
                service.captured_log()
            ));
        }
    }
    if !nodes[3]
        .3
        .captured_log()
        .contains("cold-installed application 1.0.0")
    {
        return fail("fresh install did not avoid the newer installable dead-end at 2.0.0");
    }
    for (dir, _, _, _) in &nodes[..3] {
        assign_graph(ctx, dir, &graph_at(dir, "10.0.0")?)?;
    }
    for index in [0, 1] {
        let (dir, address, _, service) = &nodes[index];
        if !wait_for_version(address, "10.0.0", CONVERGE_TIMEOUT)
            || !wait_until(CONVERGE_TIMEOUT, || confirmed(dir, "10.0.0"))
        {
            return fail(format!(
                "upgrade route did not complete:\n{}",
                service.captured_log()
            ));
        }
    }
    let stranded = &nodes[2];
    if !stranded.3.wait_for_log("no supported route", EVENT_TIMEOUT)
        || !confirmed(&stranded.0, "2.0.0")
        || stranded.3.captured_log().contains("applying update")
    {
        return fail(format!(
            "stranded node partially advanced:\n{}",
            stranded.3.captured_log()
        ));
    }
    for (index, expected) in [
        (
            0,
            vec!["1.0.0 -> 3.0.0", "3.0.0 -> 6.0.0", "6.0.0 -> 10.0.0"],
        ),
        (1, vec!["7.0.0 -> 10.0.0"]),
    ] {
        let log = nodes[index].3.captured_log();
        let mut previous = 0;
        for edge in expected {
            let at = log
                .find(&format!("applying update {edge}"))
                .ok_or_else(|| format!("missing edge {edge}:\n{log}"))?;
            if at < previous {
                return fail("upgrade hops executed out of order");
            }
            previous = at;
        }
    }
    for index in [0, 1, 3] {
        let dir = &nodes[index].0;
        assign_graph(ctx, dir, &graph_at(dir, "1.0.0")?)?;
    }
    if !nodes[0].3.wait_for_log(
        "update 7.0.0 confirmed; confirmation window passed",
        CONVERGE_TIMEOUT,
    ) {
        return fail(format!(
            "first return hop never confirmed:\n{}",
            nodes[0].3.captured_log()
        ));
    }
    let pid = pid_after(&nodes[0].3.captured_log(), "service launched agent")
        .ok_or("missing agent PID")?;
    kill_pid(pid);
    if !wait_until(EVENT_TIMEOUT, || {
        nodes[0].3.log_count("service launched agent") >= 2
    }) {
        return fail("the supervisor did not restart the agent during rollback");
    }
    for index in [0, 1, 3] {
        let (dir, address, _, service) = &nodes[index];
        if !wait_for_version(address, "1.0.0", CONVERGE_TIMEOUT)
            || !wait_until(CONVERGE_TIMEOUT, || confirmed(dir, "1.0.0"))
        {
            return fail(format!(
                "multi-hop return did not finish:\n{}",
                service.captured_log()
            ));
        }
        let log = service.captured_log();
        let mut remaining = log.as_str();
        for edge in ["10.0.0 -> 7.0.0", "7.0.0 -> 3.0.0", "3.0.0 -> 1.0.0"] {
            let marker = format!("applying update {edge}");
            let at = remaining
                .find(&marker)
                .ok_or_else(|| format!("missing or out-of-order rollback hop {edge}:\n{log}"))?;
            remaining = &remaining[at + marker.len()..];
        }
    }
    ok("four real nodes exercised branching upgrades, an installable dead end, a stranded source, and a three-hop rollback across restart");
    Ok(())
}
