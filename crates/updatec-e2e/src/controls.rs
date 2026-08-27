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
/// is bumped through [`versioned_deployment_name`] here — the throttle counts a member settled only once every
/// one of its agents reports exactly that identity, healthy. Returns the published bundle's
/// content digest, the identity every node's rejection record names it by.
///
/// Those are two writes, so between them the control plane can publish the new bytes under the
/// OLD deployment name. That interim identity is harmless and deliberately not worked around: an
/// agent reports rejection against the assignment it currently HOLDS (keyed by the application
/// digest, not by the name it was first offered under), and the planner recomputes the regression
/// verdict from live evidence every pass — so once the rename lands, the same nodes re-prove the
/// same bytes bad and the halt records that canonical identity, which is what the halt assertions poll
/// for. Closing the window would mean teaching `updatectl deploy` to own the identity too, which
/// is a change to the shipped publisher and not to this harness.
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
                    "name": versioned_deployment_name(group, version)
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
/// `heldAgents` count, the actual healthproxy-programmed EndpointSlice, and the version each node
/// reports to the control plane.
pub(crate) async fn assert_node_controls(
    layout: &FleetLayout,
    fleet: &Fleet,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use the external cohort so the assertion observes the real selectorless EndpointSlice the
    // managed healthproxy programs, rather than merely inspecting an intermediate document.
    let group = EXTERNAL_COHORT.to_string();
    let benched_ordinal = external_ordinal(0);
    let benched = format!("agent-{benched_ordinal}");
    let resource = agent_resource_name(benched_ordinal);
    let sibling_resource = agent_resource_name(external_ordinal(1));
    let address = kubectl_value("pod", &benched, "{.status.podIP}")?
        .trim()
        .to_string();
    if address.is_empty() {
        return Err(format!("{benched} has no address to verify in the EndpointSlice").into());
    }
    println!(
        "[e2e] node controls: holding and cordoning {benched} while {group} rolls to {version}"
    );

    set_agent_controls(fleet, &resource, true, true).await?;
    // The cordon must reach the real load-balancer topology BEFORE the rollout starts, or "the
    // update landed around a drained machine" is not what was tested.
    await_for(
        90,
        "the cordoned node leaves the programmed endpoints",
        || Ok(!ready_external_addresses()?.contains(&address)),
    )
    .await?;
    deploy_release(layout, fleet, std::slice::from_ref(&group), version, false).await?;

    // The group settles on the new release with its held node still on the old one: the sibling
    // advanced, the benched machine was skipped, and nothing waited on it.
    await_for(
        FLEET_ROLLOUT_TIMEOUT_SECS,
        "the group settles around the benched node",
        || {
            let advanced = reports_version(&sibling_resource, version);
            let ready =
                condition_field(&group, updatec::status_contract::READY_CONDITION, "status")
                    .as_deref()
                    == Some(updatec::status_contract::CONDITION_TRUE);
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
        || {
            Ok(reports_version(&resource, version)
                && ready_external_addresses()?.contains(&address))
        },
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
    let resource = agent_resource_name(frozen_ordinal);
    let peer_resource = agent_resource_name(external_ordinal(1));
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
        "the healthproxy drops the silent node from the programmed endpoints",
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

/// The addresses currently READY in the selectorless `external` Service — the EndpointSlice the
/// real `updated-healthproxy` programs from signed CDN health. Addresses, not pod names: the
/// healthproxy fronts machines that are not pods at all (that is the whole point of the slice), so
/// what it programs is an address literal per member and nothing else. One projection of
/// [`service_endpoints`], which is where readiness is decided for every reader of that document.
fn ready_external_addresses() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (_, endpoints) = service_endpoints(EXTERNAL_SERVICE)?;
    Ok(endpoints
        .into_iter()
        .filter(|endpoint| endpoint.ready)
        .flat_map(|endpoint| endpoint.addresses)
        .collect())
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
    run(agent_exec(pod).args(["sh", "-c", &script]))
        .map_err(|error| format!("could not send SIG{signal} to {pod}'s agent: {error}").into())
}

/// Poll `check` once a second until it holds, failing with `what` when it never does.
///
/// **The e2e's one waiting primitive**, so nothing in this binary can quietly wait for ever or
/// invent its own error tolerance. The only loops that stay hand-rolled are the ones this shape
/// cannot express: a wait carrying per-iteration state (`Chaos::run_generation`'s incremental
/// settle tracking, `Chaos::converge`'s freeze-paused clock), and a wait with an immediate hard
/// failure inside it (`assert_set_isolation`'s cross-set endpoint).
pub(crate) async fn await_for(
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

/// Scenario: the `onRegression: rollback` response, end to end
/// (docs/regression-response-design.md).
///
/// One cohort's governing sets — its own and the fleet-wide throttle set, because automatic
/// movement requires every governing set's consent — are flipped to `rollback`, and a broken
/// release is rolled at the cohort. Its first node attempts the bytes, durably rejects them, and
/// restores its predecessor: the successful-rollback gate the response waits for. The control
/// plane then answers the halt by rebasing the group onto the predecessor and durably vetoing the
/// bad body, and says so on the set's own halt record (`rolledBack`).
///
/// The controller is restarted to prove the veto is a RECORD, not a memory: with every node
/// reassigned to the predecessor, no live report names the bad assignment any more, so only the
/// admitted-state document's `vetoed.json` keeps the proven-bad body refused. Corrected bytes —
/// a new digest — are the exit, exactly as for a plain halt, and clear the record.
pub(crate) async fn assert_regression_rollback(
    layout: &FleetLayout,
    fleet: &Fleet,
    bad_version: &str,
    fixed_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cohort = 0usize;
    let group = cohort_group(cohort);
    let set = set_name(cohort_set_index(cohort));
    let bad_deployment = versioned_deployment_name(&group, bad_version);
    let members: Vec<(String, String)> = (0..COHORT_SIZE)
        .map(|index| {
            let ordinal = cohort * COHORT_SIZE + index;
            (format!("agent-{ordinal}"), agent_resource_name(ordinal))
        })
        .collect();
    let held_version = kubectl_value("updateagent", &members[0].1, "{.status.reportedVersion}")?
        .trim()
        .to_string();
    println!(
        "[e2e] regression rollback: {group} (sets {set} + {FLEET_SET}) holds {held_version}; \
         rolling broken {bad_version} under onRegression=rollback"
    );

    let set_response = |response: &str| {
        let patch = serde_json::json!({"spec": {"onRegression": response}});
        let sets = fleet.sets();
        let names = [set.clone(), FLEET_SET.to_string()];
        async move {
            for name in &names {
                sets.patch(name, &PatchParams::default(), &Patch::Merge(patch.clone()))
                    .await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
    };
    set_response("rollback").await?;

    let bad_sha = deploy_release(
        layout,
        fleet,
        std::slice::from_ref(&group),
        bad_version,
        true,
    )
    .await?;

    // The node-level containment the response's gate waits for: every member healthy on the
    // predecessor again, and the attempting node carrying the durable rejection of these bytes.
    await_for(
        240,
        "the cohort to contain the broken release and hold its predecessor",
        || {
            Ok(members
                .iter()
                .all(|(_, resource)| reports_version(resource, &held_version))
                && members
                    .iter()
                    .any(|(pod, _)| rejected_release(pod, &bad_sha)))
        },
    )
    .await?;

    // The response itself: the halt record on the set says the groups were rolled back.
    await_for(
        120,
        "the set to record the halt as answered by a rollback",
        || {
            Ok(halted_deployments(&set).contains(&bad_deployment)
                && halt_rolled_back(&set, &bad_deployment))
        },
    )
    .await?;
    println!("[e2e] the response rebased {group} and vetoed {bad_deployment}");

    // The restart shape: the rebased nodes' reports no longer name the bad assignment, so the
    // recomputed verdict has NO live evidence — only the durable veto can carry the halt across
    // a controller restart.
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "restart",
        "deployment/updatec-controller",
    ]))?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "deployment/updatec-controller",
        "--timeout=180s",
    ]))?;
    await_for(
        120,
        "the veto to carry the halt across the controller restart",
        || {
            Ok(halted_deployments(&set).contains(&bad_deployment)
                && halt_rolled_back(&set, &bad_deployment)
                && members
                    .iter()
                    .all(|(_, resource)| reports_version(resource, &held_version)))
        },
    )
    .await?;
    println!("[e2e] the veto survived the controller restart with no live evidence behind it");

    // Corrected bytes are the exit: a new digest is admitted normally, the cohort converges, and
    // once nothing names the vetoed body any more its record — and the halt — are gone.
    deploy_release(
        layout,
        fleet,
        std::slice::from_ref(&group),
        fixed_version,
        false,
    )
    .await?;
    await_for(
        240,
        "the cohort to converge onto the corrected release",
        || {
            Ok(members
                .iter()
                .all(|(_, resource)| reports_version(resource, fixed_version)))
        },
    )
    .await?;
    await_for(
        120,
        "the answered halt to clear once nothing names the body",
        || Ok(!halted_deployments(&set).contains(&bad_deployment)),
    )
    .await?;
    set_response("halt").await?;
    println!(
        "[e2e] regression rollback verified: contained, rebased, vetoed across a restart, and \
         released by corrected bytes"
    );
    Ok(())
}

/// Scenario: the dependency dataflow, end to end (docs/node-reconciler-protocol.md — outputs).
///
/// A consumer group is wired to a producer sibling: `dependsOn` orders it behind the producer,
/// and a named input references the producer's `release.version` output — the file each producer
/// node's reconciler writes into `--output-dir`, the agent publishes to private S3 and binds to its
/// signed report, the control plane resolves into the consumer's signed assignment, and the
/// consumer's agent materializes in `--input-dir`. The assertion walks that whole chain twice:
/// once at wiring (the consumer's nodes receive the producer's CURRENT version), and again after
/// the producer upgrades — a body change that renames nothing on the consumer, staged purely by
/// the configuration digest its resolved inputs changed.
pub(crate) async fn assert_dataflow_inputs(
    layout: &FleetLayout,
    fleet: &Fleet,
    producer_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let producer_cohort = 2usize;
    let consumer_cohort = 3usize;
    let producer = cohort_group(producer_cohort);
    let consumer = cohort_group(consumer_cohort);
    let consumer_pods: Vec<String> = (0..COHORT_SIZE)
        .map(|index| format!("agent-{}", consumer_cohort * COHORT_SIZE + index))
        .collect();
    let held_version = kubectl_value(
        "updateagent",
        &agent_resource_name(producer_cohort * COHORT_SIZE),
        "{.status.reportedVersion}",
    )?
    .trim()
    .to_string();
    println!(
        "[e2e] dataflow: wiring {consumer} to consume {producer}'s release.version output \
         (currently {held_version})"
    );
    fleet
        .groups()
        .patch(
            &consumer,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {
                "dependsOn": [producer],
                "inputs": {"upstream_release": {"group": producer, "output": "release.version"}}
            }})),
        )
        .await?;

    // The value each consumer reconciler observed, decoded from the durable output snapshot the
    // agent publishes after the invocation. Input directories are deliberately ephemeral, so the
    // fixture re-advertises only this public release version as `observed.upstream_release`; the
    // chain is proven only when EVERY consumer node carries the exact bytes.
    let inputs_carry = |value: &str| -> bool {
        consumer_pods.iter().all(|pod| {
            output(agent_exec(pod).args([
                "sh",
                "-c",
                "for file in /var/lib/updated/providers/outputs/*.json; do \
                 cat \"$file\" 2>/dev/null && printf '\\n'; done",
            ]))
            .is_ok_and(|inputs| {
                inputs.lines().any(|line| {
                    serde_json::from_str::<updated_contracts::dataflow::FileSnapshot>(line)
                        .ok()
                        .and_then(|snapshot| {
                            snapshot.files.get("observed.upstream_release").cloned()
                        })
                        .and_then(|file| file.bytes().ok())
                        .is_some_and(|bytes| bytes == value.as_bytes())
                })
            })
        })
    };
    await_for(
        180,
        "the consumer nodes to receive the producer's current version as a file input",
        || Ok(inputs_carry(&held_version)),
    )
    .await?;

    // The producer moves; nothing about the consumer is renamed. Its resolved inputs change, which
    // changes the configuration digest it is published under, which is a real staged change its
    // nodes must receive — the exact path a name-only comparison would have dropped for ever.
    deploy_release(
        layout,
        fleet,
        std::slice::from_ref(&producer),
        producer_version,
        false,
    )
    .await?;
    await_for(
        300,
        "the producer's upgrade to propagate into the consumer's inputs",
        || Ok(inputs_carry(producer_version)),
    )
    .await?;

    // Unwire, so later scenarios meet the same ungated groups every earlier one did. JSON merge
    // patch replaces ARRAYS wholesale but MERGES objects — an empty `inputs` map would leave the
    // reference standing (with dependsOn now empty, an invalid wiring that quarantines the
    // group), so the map key is deleted explicitly with the merge-patch null.
    fleet
        .groups()
        .patch(
            &consumer,
            &PatchParams::default(),
            &Patch::Merge(
                serde_json::json!({"spec": {"dependsOn": [], "inputs": {"upstream_release": null}}}),
            ),
        )
        .await?;
    println!(
        "[e2e] dataflow verified: {producer}'s signed output reached every {consumer} node's \
         reconciler, and its upgrade re-staged the consumer with no rename"
    );
    Ok(())
}

/// Scenario: the rollout schedule freezes a set, and `emergencyCorrection` — and only it — goes
/// through (docs, `UpdateGroupSpec::emergency_correction`).
///
/// The governing set is given a schedule whose only window is hours away, a release is rolled at
/// its group, and the freeze is asserted as a RECORD (`status.frozen`) plus the absence of any
/// movement. The operator then states the deployment is an emergency correction: the schedule is
/// waived, the group converges, and the set says so (`status.emergency`).
pub(crate) async fn assert_schedule_freeze_and_emergency(
    layout: &FleetLayout,
    fleet: &Fleet,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cohort = 8usize;
    let group = cohort_group(cohort);
    let set = set_name(cohort_set_index(cohort));
    let member = agent_resource_name(cohort * COHORT_SIZE);
    let held_version = kubectl_value("updateagent", &member, "{.status.reportedVersion}")?
        .trim()
        .to_string();
    // A one-minute daily window six hours from now: deterministically closed for this run,
    // whatever wall-clock hour the suite happens to execute at.
    let opens = (chrono::Utc::now() + chrono::Duration::hours(6)).format("%H:%M");
    let closes = (chrono::Utc::now() + chrono::Duration::hours(6) + chrono::Duration::minutes(1))
        .format("%H:%M");
    println!(
        "[e2e] schedule: freezing {set} (window {opens}-{closes} UTC) and rolling {version} at {group}"
    );
    fleet
        .sets()
        .patch(
            &set,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"rolloutWindows": [
                {"start": opens.to_string(), "end": closes.to_string()}
            ]}})),
        )
        .await?;
    deploy_release(layout, fleet, std::slice::from_ref(&group), version, false).await?;

    // The freeze must be recorded AND hold: the set says frozen, and after a generous window the
    // member still runs what it ran. Fifteen seconds is several reconciles and several agent
    // check intervals, so "it did not move" is a property of the planner, not of sampling.
    await_for(60, "the set to record its schedule freeze", || {
        Ok(kubectl_value("updategroupset", &set, "{.status.frozen}")
            .is_ok_and(|frozen| frozen.trim() == "true"))
    })
    .await?;
    tokio::time::sleep(Duration::from_secs(15)).await;
    if !reports_version(&member, &held_version) {
        return Err(format!(
            "{group} moved off {held_version} while its set's schedule was closed"
        )
        .into());
    }

    // The operator states the emergency; the schedule — and only the schedule — is waived.
    fleet
        .groups()
        .patch(
            &group,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"emergencyCorrection": true}})),
        )
        .await?;
    await_for(60, "the set to record the emergency correction", || {
        Ok(
            kubectl_value("updategroupset", &set, "{.status.emergency[*]}")
                .is_ok_and(|emergency| emergency.split_whitespace().any(|name| name == group)),
        )
    })
    .await?;
    await_for(
        240,
        "the emergency correction to converge through the freeze",
        || {
            Ok((0..COHORT_SIZE).all(|index| {
                reports_version(&agent_resource_name(cohort * COHORT_SIZE + index), version)
            }))
        },
    )
    .await?;
    fleet
        .groups()
        .patch(
            &group,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"emergencyCorrection": false}})),
        )
        .await?;
    fleet
        .sets()
        .patch(
            &set,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"rolloutWindows": []}})),
        )
        .await?;
    println!(
        "[e2e] schedule verified: the freeze held movement and the stated emergency went through"
    );
    Ok(())
}

/// Scenario: an invalid group spec fails CLOSED (domain.rs — quarantine).
///
/// A group's deployment is corrupted to a digest no release could carry. The control plane must
/// quarantine the group — its own status names the failure — while every node it selects keeps
/// running and reporting exactly what it ran: the one outcome quarantine exists to prevent is
/// those nodes being handed the ungated `defaultDeployment` because their group stopped planning.
pub(crate) async fn assert_quarantine_fails_closed(
    fleet: &Fleet,
) -> Result<(), Box<dyn std::error::Error>> {
    let cohort = 10usize;
    let group = cohort_group(cohort);
    let members: Vec<String> = (0..COHORT_SIZE)
        .map(|index| agent_resource_name(cohort * COHORT_SIZE + index))
        .collect();
    let held_version = kubectl_value("updateagent", &members[0], "{.status.reportedVersion}")?
        .trim()
        .to_string();
    let valid_sha = kubectl_value(
        "updategroup",
        &group,
        "{.spec.deployment.application.sha256}",
    )?
    .trim()
    .to_string();
    println!(
        "[e2e] quarantine: corrupting {group}'s deployment digest while it serves {held_version}"
    );
    fleet
        .groups()
        .patch(
            &group,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"deployment": {"application": {
                "sha256": "z".repeat(64)
            }}}})),
        )
        .await?;
    await_for(
        60,
        "the group to be quarantined for its invalid deployment",
        || {
            Ok(
                condition_field(&group, updatec::status_contract::READY_CONDITION, "reason")
                    .is_some_and(|reason| reason == "InvalidDeployment"),
            )
        },
    )
    .await?;
    // Fail-closed means the selected nodes are exactly where they were: same version, still
    // ready, for longer than several reconciles could have moved them.
    tokio::time::sleep(Duration::from_secs(15)).await;
    for member in &members {
        if !reports_version(member, &held_version) {
            return Err(format!(
                "{member} left {held_version} while its group was quarantined — an ungated swap"
            )
            .into());
        }
    }
    fleet
        .groups()
        .patch(
            &group,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"deployment": {"application": {
                "sha256": valid_sha
            }}}})),
        )
        .await?;
    await_for(120, "the repaired group to plan again", || {
        Ok(
            condition_field(&group, updatec::status_contract::READY_CONDITION, "reason")
                .is_some_and(|reason| reason != "InvalidDeployment"),
        )
    })
    .await?;
    println!("[e2e] quarantine verified: the broken spec froze the group and moved nobody");
    Ok(())
}

/// Every sample line of one series in a Prometheus text exposition, as (label set, value) — the
/// label set including its braces, or empty for an unlabeled series.
///
/// Both expositions write their `# HELP`/`# TYPE` comments unconditionally, before the loop that
/// writes the data, so a substring search for a series NAME passes against a document carrying no
/// series at all: zero planned groups, zero programmed backends, a projection never once read.
/// That is exactly the state the assertion below exists to disprove, so it reads values instead.
fn samples<'a>(exposition: &'a str, name: &str) -> Vec<(&'a str, f64)> {
    exposition
        .lines()
        .filter_map(|line| {
            // The name must be followed by the label set or the value separator, or
            // `updatec_reports_fresh` would also match `updatec_reports_fresh_total`.
            let (labels, value) = match line.strip_prefix(name)?.split_once(' ') {
                Some(("", value)) => ("", value),
                Some((labels, value)) if labels.starts_with('{') && labels.ends_with('}') => {
                    (labels, value)
                }
                _ => return None,
            };
            Some((labels, value.trim().parse().ok()?))
        })
        .collect()
}

/// Scenario: the observability expositions serve, from inside the cluster, the gauges the
/// alerting and dashboards are built on — the controller's planner projection
/// (`docs/observability-design.md`) and the operator-managed healthproxy's membership view.
///
/// Each series is asserted on its VALUES, never on its name: the names are in unconditional HELP
/// comments, so a name check certifies an exposition that projected nothing. The healthproxy's two
/// freshness stamps are the sharp end of that — a zero in either means the document that governs
/// cordons, or the one that governs readiness, was never once read, which is precisely the failure
/// `docs/observability-design.md` says these series exist to make alertable.
pub(crate) async fn assert_metrics_exposed() -> Result<(), Box<dyn std::error::Error>> {
    let controller = pod_ip_by_app("updatec-controller")?;
    let controller_metrics = cluster_curl(&format!("http://{controller}:9090/metrics"))?;
    // The generation the controller published, per deployment: a real generation is >= 1, and the
    // series is declared but carries no SAMPLE when nothing has been published, so an empty list is
    // the failure — the same reason every assertion here reads values rather than names.
    let generations = samples(&controller_metrics, "updatec_generation");
    if generations.is_empty() || generations.iter().any(|(_, value)| *value < 1.0) {
        return Err(format!(
            "controller exposition carries no published generation: {generations:?}"
        )
        .into());
    }
    // Every cohort agent reports; the fleet has converged, so the freshness gate must be counting
    // at least the cohort fleet. (A floor, not equality: the externals and the Jenkins/HAProxy
    // tiers report too, and one of them restarting must not flake the assertion.)
    let fresh = samples(&controller_metrics, "updatec_reports_fresh");
    match fresh.as_slice() {
        [("", value)] if *value >= NODE_COUNT as f64 => {}
        _ => {
            return Err(format!(
                "controller exposition reports fewer than the fleet's {NODE_COUNT} fresh reports: {fresh:?}"
            )
            .into())
        }
    }
    // The one-hot projection: one sample per (group, state), exactly one of which is 1 per group.
    // Both halves matter — that every cohort is projected, and that the projection is one-hot
    // rather than an all-zero block a dashboard would read as "no group is anywhere".
    let progress = samples(&controller_metrics, "updatec_group_progress");
    let hot = progress.iter().filter(|(_, value)| *value == 1.0).count();
    if hot < COHORT_COUNT {
        return Err(format!(
            "controller exposition projects a verdict for {hot} groups, not the fleet's \
             {COHORT_COUNT}: {progress:?}"
        )
        .into());
    }
    let healthproxy = pod_ip_by_app("updated-backend-external")?;
    let healthproxy_metrics = cluster_curl(&format!(
        "http://{healthproxy}:{}/metrics",
        updatec::runtime::BACKEND_METRICS_PORT
    ))?;
    // The external slice converged above, so its members are programmed up — a `state="up"` of 0
    // is a proxy that programmed nothing and would satisfy any name-only check.
    let up = samples(&healthproxy_metrics, "healthproxy_backends")
        .into_iter()
        .find(|(labels, _)| *labels == "{state=\"up\"}")
        .map(|(_, value)| value);
    if up.is_none_or(|value| value < 1.0) {
        return Err(format!(
            "healthproxy exposition programs no ready backend (state=\"up\" is {up:?})"
        )
        .into());
    }
    // Zero means the fleet report index was never once read — a fleet-wide drain waiting to
    // happen when no cached report exists.
    for series in ["healthproxy_reports_timestamp_seconds"] {
        match samples(&healthproxy_metrics, series).as_slice() {
            [("", value)] if *value > 0.0 => {}
            other => {
                return Err(format!(
                    "healthproxy exposition never observed the document behind {series}: {other:?}"
                )
                .into())
            }
        }
    }
    println!("[e2e] metrics verified: controller and healthproxy expositions serve their gauges");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::samples;

    /// The property the metrics scenario rests on: a document that declares a series but carries
    /// no data yields NO samples. A `contains("updatec_group_progress")` passes on exactly this
    /// text — a controller that planned zero groups — which is why the assertion reads values.
    #[test]
    fn a_declared_but_empty_series_yields_no_samples() {
        let empty =
            "# HELP updatec_group_progress One-hot projection of the planner verdict per group.\n\
                     # TYPE updatec_group_progress gauge\n";
        assert!(empty.contains("updatec_group_progress"));
        assert!(samples(empty, "updatec_group_progress").is_empty());
    }

    /// Sample lines are read as (labels, value), and a series name is matched only where it names
    /// the series — never as the prefix of a longer one, which would read a neighbour's value.
    #[test]
    fn samples_read_values_and_do_not_match_a_longer_series_name() {
        let text = "# TYPE updatec_reports_fresh gauge\n\
                    updatec_reports_fresh 34\n\
                    updatec_reports_fresh_total 999\n\
                    updatec_group_progress{group=\"cohort-00\",state=\"settled\"} 1\n\
                    updatec_group_progress{group=\"cohort-00\",state=\"failed\"} 0\n";
        assert_eq!(samples(text, "updatec_reports_fresh"), vec![("", 34.0)]);
        assert_eq!(
            samples(text, "updatec_group_progress"),
            vec![
                ("{group=\"cohort-00\",state=\"settled\"}", 1.0),
                ("{group=\"cohort-00\",state=\"failed\"}", 0.0),
            ]
        );
    }
}
