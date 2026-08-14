use crate::*;
use kube::api::{Patch, PatchParams};
use std::time::Duration;

/// The ONE path a release reaches this fleet by, shared with every scenario that publishes.
/// Publish one release major — a valid sample app, or an intentionally corrupt entrypoint
/// every agent rejects at activation — and roll `groups` to it through the real **`updatectl
/// deploy`**: the CI release tool builds the deterministic bundle, signs it, publishes it to
/// the release repository (MinIO), and merge-patches each group's `application`. It runs
/// inside the release-server pod, the one place that holds the repository's signing keys,
/// reaches MinIO, and carries `updatectl` — the same executor that seeded the baseline.
///
/// `updatectl deploy` patches the application ref but not the deployment *identity*, so that
/// is bumped to `group@version` here — the throttle counts a member settled only once every
/// one of its agents reports exactly that identity, healthy. Returns the published bundle's
/// content digest, the identity every node's rejection record names it by.
pub(crate) async fn deploy_release(
    layout: &FleetLayout,
    fleet: &Fleet,
    groups: &[String],
    version: &str,
    broken: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let entrypoint = if broken {
        "printf 'intentionally corrupt entrypoint\\n' >/tmp/gen/bin/app"
    } else {
        "cp /usr/local/bin/sampleapp /tmp/gen/bin/app"
    };
    let repository = release_repository_flags();
    let FleetLayout {
        platform,
        provider_path,
        provider_sha,
    } = layout;
    let deploys = groups
        .iter()
        .map(|group| {
            format!(
                "updatectl deploy --keys-dir /data/release-keys {repository} \
                 --namespace {NAMESPACE} --group {group} --product app --channel stable \
                 --version {version} --entrypoint bin/app --platform {platform} \
                 --source /tmp/gen --provider-set-path {provider_path} \
                 --provider-set-sha256 {provider_sha}"
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let script = format!(
        "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
         rm -rf /tmp/gen && mkdir -p /tmp/gen/bin /tmp/gen/config; {entrypoint}; \
         chmod 0755 /tmp/gen/bin/app; \
         printf 'version = \"{version}\"\\n' >/tmp/gen/config/release.toml; {deploys}"
    );
    let status = tokio::process::Command::new("kubectl")
        .args(kubectl_context_args())
        .args(RELEASE_SERVER_EXEC)
        .args(["--", "sh", "-c", &script])
        .status()
        .await?;
    if !status.success() {
        return Err(format!("updatectl deploy failed for {version}").into());
    }
    for group in groups {
        fleet
            .groups()
            .patch(
                group,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec":{"deployment":{
                    "name": format!("{group}@{version}")
                }}})),
            )
            .await?;
    }
    let first = groups.first().ok_or("a deploy needs at least one group")?;
    kubectl_value(
        "updategroup",
        first,
        "{.spec.deployment.application.sha256}",
    )
}

/// Scenario: the per-node operational controls, against the live control plane.
///
/// An operator benches ONE machine mid-fleet — `cordon` to take it out of rotation, `hold` to
/// freeze it on exactly what it runs — then rolls a release at its group. The two controls compose
/// (`docs/node-controls-design.md`): hold decides ROUTING (the node is never moved) and cordon
/// decides ACCOUNTING (it is absent from the availability budget and from settlement), so the
/// group's OTHER node takes the release and the group settles around the benched machine instead of
/// waiting on it for ever. Clearing both returns it to ordinary admission and it converges.
///
/// Every assertion is a record: the agent's own status, the group's published condition and
/// `heldAgents` count, the endpoint projection the cordon actually travels through, and the
/// version each node reports to the control plane.
pub(crate) async fn assert_node_controls(
    layout: &FleetLayout,
    fleet: &Fleet,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // A cohort in an ODD set, so this never lands on a group the chaos generation rejected a
    // release on: those groups are halted on their own bodies and would refuse admission for a
    // reason that has nothing to do with node controls.
    let cohort = GROUPS_PER_SET;
    let group = cohort_group(cohort);
    let benched_ordinal = cohort * COHORT_SIZE;
    let benched = format!("agent-{benched_ordinal}");
    let resource = agent_resource_name(benched_ordinal as u8);
    let sibling_resource = agent_resource_name(benched_ordinal as u8 + 1);
    println!(
        "[e2e] node controls: holding and cordoning {benched} while {group} rolls to {version}"
    );

    set_agent_controls(fleet, &resource, true, true).await?;
    // The cordon must reach the healthproxy BEFORE the rollout starts, or "the update landed around
    // a drained machine" is not what was tested.
    await_for(90, "the cordoned node is published as drained", || {
        Ok(drained_nodes()?.contains(&resource))
    })
    .await?;
    deploy_release(layout, fleet, std::slice::from_ref(&group), version, false).await?;

    // The group settles on the new release with its held node still on the old one: the sibling
    // advanced, the benched machine was skipped, and nothing waited on it.
    await_for(
        FLEET_ROLLOUT_TIMEOUT_SECS,
        "the group settles around the benched node",
        || {
            let advanced = reports_version(&sibling_resource, version);
            let ready = condition_status(&group, "Ready").as_deref() == Some("True");
            Ok(advanced && ready)
        },
    )
    .await?;
    if reports_version(&resource, version) {
        return Err(
            format!("{benched} was held, so it must NOT have been moved to {version}").into(),
        );
    }
    let held_agents = kubectl_value("updategroup", &group, "{.status.heldAgents}")?;
    if held_agents.trim() != "1" {
        return Err(format!(
            "{group}.status.heldAgents reads {held_agents:?}; a forgotten hold must be a visible \
             count, not a mystery"
        )
        .into());
    }
    if !agent_status_flag(&resource, "cordoned") || !agent_status_flag(&resource, "held") {
        return Err(format!("{resource}'s own status does not carry its hold and cordon").into());
    }
    println!(
        "[e2e] verified the benched node was skipped ({group} settled on {version} with \
         heldAgents=1) while it stayed drained"
    );

    // The operator finishes the maintenance: both controls are cleared, and the machine rejoins
    // ordinary admission — no special case, just a candidate under `maxUnavailable`.
    set_agent_controls(fleet, &resource, false, false).await?;
    await_for(
        FLEET_ROLLOUT_TIMEOUT_SECS,
        "the released node converges and returns to rotation",
        || Ok(reports_version(&resource, version) && !drained_nodes()?.contains(&resource)),
    )
    .await?;
    println!("[e2e] verified the released node converged onto {version} and left the drain list");
    Ok(())
}

/// Scenario: staleness fails CLOSED, against the out-of-cluster slice the real
/// `updated-healthproxy` fronts.
///
/// One node's agent is stopped mid-fleet — the workload keeps running and keeps answering, so this
/// is precisely "the machine stopped REPORTING", the one failure the control plane can never
/// distinguish from a lie. Two things must follow, and neither may wait for a human: the rollout
/// must not advance past it (a node nothing is known about is unavailable, and it spends the
/// group's whole budget), and the healthproxy must take it out of rotation. Restarting the agent
/// must recover both without any operator action.
pub(crate) async fn assert_staleness_fails_closed(
    layout: &FleetLayout,
    fleet: &Fleet,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let frozen_ordinal = external_ordinal(0);
    let frozen = format!("agent-{frozen_ordinal}");
    let resource = agent_resource_name(frozen_ordinal as u8);
    let peer_resource = agent_resource_name(external_ordinal(1) as u8);
    // The address the healthproxy programs for this machine: what it publishes is an address per
    // member, because the slice exists for machines that are not pods.
    let address = kubectl_value("pod", &frozen, "{.status.podIP}")?
        .trim()
        .to_string();
    if address.is_empty() {
        return Err(format!("{frozen} has no address to look for in the projection").into());
    }
    println!("[e2e] staleness: stopping {frozen}'s agent while its workload keeps serving");
    signal_agent(&frozen, "STOP")?;

    // The report ages out of `REPORT_FRESHNESS` and the healthproxy — reading the same signed
    // reports from the CDN — drops the node from the Service it programs. This is the projection
    // the product path actually uses for machines outside Kubernetes.
    await_for(
        REPORT_FRESHNESS_SECS + 60,
        "the healthproxy drops the silent node from the endpoint projection",
        || Ok(!ready_external_addresses()?.contains(&address)),
    )
    .await?;
    println!("[e2e] the silent node left the healthproxy-programmed endpoints");

    // Only now is a release rolled at the group: the slot the silent node occupies must HOLD the
    // rollout — its peer is healthy and the budget is one, so a control plane that treated silence
    // as "fine" would move the peer and take the whole slice down.
    deploy_release(
        layout,
        fleet,
        &[EXTERNAL_COHORT.to_string()],
        version,
        false,
    )
    .await?;
    for _ in 0..STALENESS_HOLD_SECS {
        if reports_version(&peer_resource, version) {
            return Err(format!(
                "{peer_resource} was moved to {version} while its group's other node was silent: the \
                 rollout advanced past a node nothing is known about"
            )
            .into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!("[e2e] the rollout held for {STALENESS_HOLD_SECS}s rather than advancing past the silent node");

    // The agent is restarted. It reports again, the freshness gate reopens, the rollout resumes,
    // and the healthproxy returns the node to rotation — all without an operator touching anything.
    signal_agent(&frozen, "CONT")?;
    await_for(
        FLEET_ROLLOUT_TIMEOUT_SECS,
        "the slice converges and returns to rotation once the agent reports again",
        || {
            let converged = [&resource, &peer_resource]
                .iter()
                .all(|node| reports_version(node, version));
            Ok(converged && ready_external_addresses()?.contains(&address))
        },
    )
    .await?;
    println!("[e2e] verified the slice recovered: both nodes on {version} and back in rotation");
    Ok(())
}

/// Set (or clear) an agent's operator controls and wait for the patch to be accepted.
async fn set_agent_controls(
    fleet: &Fleet,
    resource: &str,
    hold: bool,
    cordon: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    fleet
        .agents()
        .patch(
            resource,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"hold": hold, "cordon": cordon}})),
        )
        .await?;
    Ok(())
}

/// Whether the control plane records this node as healthy on exactly `version` — its own last
/// signed report, projected onto the `UpdateAgent` status. Read blocking, like every other
/// assertion in this module, so one waiting primitive covers them all.
fn reports_version(resource: &str, version: &str) -> bool {
    kubectl_value(
        "updateagent",
        resource,
        "{.status.reportedVersion} {.status.reportedReady}",
    )
    .is_ok_and(|value| value.trim() == format!("{version} true"))
}

/// Whether an `UpdateAgent`'s own status carries `flag` as true.
fn agent_status_flag(resource: &str, flag: &str) -> bool {
    kubectl_value("updateagent", resource, &format!("{{.status.{flag}}}"))
        .is_ok_and(|value| value.trim() == "true")
}

/// The nodes the control plane currently publishes as DRAINED in its endpoint projection — the one
/// channel a cordon travels to the healthproxy. Read from the object store the projection is
/// written to, not from any CR, so this asserts the channel rather than the intent.
fn drained_nodes() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let document = output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "curl",
        "-sf",
        &updated_contracts::endpoints::endpoints_url(HEALTH_CDN),
    ]))?;
    let parsed: serde_json::Value = serde_json::from_str(&document)?;
    Ok(parsed["drained"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| node.as_str().map(str::to_string))
        .collect())
}

/// The addresses currently READY in the selectorless `external` Service — the EndpointSlice the
/// real `updated-healthproxy` programs from signed CDN health. Addresses, not pod names: the
/// healthproxy fronts machines that are not pods at all (that is the whole point of the slice), so
/// what it programs is an address literal per member and nothing else.
fn ready_external_addresses() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let json = output(kubectl().args([
        "-n",
        NAMESPACE,
        "get",
        "endpointslices",
        "-l",
        &format!("kubernetes.io/service-name={EXTERNAL_SERVICE}"),
        "-o",
        "json",
    ]))?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    let mut ready = Vec::new();
    for slice in parsed["items"].as_array().into_iter().flatten() {
        for endpoint in slice["endpoints"].as_array().into_iter().flatten() {
            if endpoint["conditions"]["ready"].as_bool().unwrap_or(false) {
                for address in endpoint["addresses"].as_array().into_iter().flatten() {
                    if let Some(address) = address.as_str() {
                        ready.push(address.to_string());
                    }
                }
            }
        }
    }
    Ok(ready)
}

/// Stop or resume a node's agent process without touching its workload.
///
/// The signal is delivered by name through `/proc`, because the node image is plain Ubuntu with no
/// `procps`: the point is to leave the machine RUNNING and serving while it stops reporting, which
/// is the failure a stale report has to fail closed on. Deleting the pod would prove something
/// else entirely (the workload would go with it).
///
/// Only the agent is signalled. Its launcher relaunches an agent that EXITS; a stopped one has not
/// exited, so it stays stopped and stays silent — which is the state under test — and the launcher
/// brings it straight back on `CONT` if it ever does exit.
fn signal_agent(pod: &str, signal: &str) -> Result<(), Box<dyn std::error::Error>> {
    let script = format!(
        "set -e; found=0; for d in /proc/[0-9]*; do \
           c=$(cat $d/comm 2>/dev/null || true); \
           case \"$c\" in updated-agent) kill -{signal} ${{d#/proc/}} && found=1;; esac; \
         done; [ $found = 1 ]"
    );
    run(kubectl().args([
        "-n", NAMESPACE, "exec", pod, "-c", "agent", "--", "sh", "-c", &script,
    ]))
    .map_err(|error| format!("could not send SIG{signal} to {pod}'s agent: {error}").into())
}

/// Poll `check` once a second until it holds, failing with `what` when it never does. The e2e's one
/// waiting primitive for the scenarios below, so a scenario cannot quietly wait for ever.
async fn await_for(
    seconds: usize,
    what: &str,
    mut check: impl FnMut() -> Result<bool, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last = String::new();
    for second in 0..seconds {
        match check() {
            Ok(true) => return Ok(()),
            Ok(false) => last.clear(),
            // A transient API or exec failure is not a verdict: it is retried like a false, and
            // reported only if the wait as a whole runs out.
            Err(error) => last = error.to_string(),
        }
        if second % 15 == 0 && second > 0 {
            println!("[e2e] waiting for {what} ({second}/{seconds}s)");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!(
        "timed out after {seconds}s waiting for {what}{}{last}",
        if last.is_empty() {
            ""
        } else {
            "; last error: "
        }
    )
    .into())
}
