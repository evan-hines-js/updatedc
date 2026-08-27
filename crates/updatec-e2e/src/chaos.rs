use crate::*;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams};
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;
use std::time::Instant;

/// The seeded fleet-chaos generation: one cohort group per set is rolled — the even sets to a
/// signed but unlaunchable release, the odd sets to a valid one — under pod-kill and
/// controller-crash disruption, while each set's other group keeps serving. The fleet must settle
/// with every broken cohort back on its exact predecessor, *provably* having attempted and
/// rejected the broken release, and every valid cohort advanced. A convergence pass then lifts all
/// cohorts, exercised and untouched alike, onto one new version above both.
#[derive(Clone)]
pub(crate) struct Chaos {
    pub(crate) fleet: Fleet,
    /// The signed identities every release this run publishes is built from — the ONE description
    /// of "how to publish a release into this fleet", shared with the node-control and staleness
    /// scenarios so there is a single publishing path.
    pub(crate) layout: FleetLayout,
}

impl Chaos {
    /// Diverge the fleet from the baseline through one broken and one valid release, then
    /// converge every cohort onto a single new version above both.
    pub(crate) async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let baseline = version_major(BASELINE_VERSION).ok_or("unparseable baseline version")?;
        let (bad_major, good_major, converge_major) = (baseline + 1, baseline + 2, baseline + 3);
        self.run_generation(CHAOS_SEED, bad_major, good_major)
            .await?;
        self.converge(converge_major).await
    }

    /// Roll the broken `bad_major` to the even sets' exercised cohort and the valid `good_major`
    /// to the odd sets', inject stateless pod-kill chaos into them, then wait for the fleet to
    /// settle. Settled means: every broken cohort's nodes are healthy on the release *below* the
    /// broken one and each carries the durable rejection record naming the broken release's own
    /// bytes (live nodes hold their predecessor; killed cold nodes descend through signed ordered
    /// fallback), and every valid cohort's nodes are healthy on the new version.
    ///
    /// All exercised cohorts are patched at once; the control plane's fleet set does the pacing,
    /// keeping [`FLEET_CONCURRENCY`] rolling at a time in set order. Roles alternate by set — even
    /// sets take the broken release (roll back), odd sets the valid one (roll forward) — so the
    /// pipeline always carries a mix in flight.
    async fn run_generation(
        &self,
        seed: u64,
        bad_major: usize,
        good_major: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let good_version = format!("{good_major}.0.0");
        let bad_version = format!("{bad_major}.0.0");
        // EVERY group of every set is exercised, both of each set's two. The set's own throttle
        // still admits one at a time, so its other group keeps serving while the first rolls
        // ([`UPTIME_MARGIN`]) — and the second only starts once the first has released the slot.
        //
        // That second half is the regression test for the planner's done-failed verdict. A cohort
        // that rolls back never reports the identity it was assigned, so its group used to stay
        // "rolling" for ever and hold its set's single slot for ever; queueing a sibling behind it
        // waited on a rollout the control plane would never finish, which is why this generation
        // used to drive one group per set. The rejecting group now ends its rollout — durable
        // rejection is the evidence, and the group is released rather than in flight — so the
        // sibling below MUST advance inside this same generation.
        let exercised: Vec<usize> = (0..COHORT_COUNT).collect();
        // The BROKEN release goes to the first group of each even set: the one the set admits
        // first, so the sibling queued behind it is the one whose progress proves the slot was
        // released. Every other group takes the valid release.
        let is_broken = |cohort: &usize| {
            cohort.is_multiple_of(GROUPS_PER_SET) && cohort_set_index(*cohort).is_multiple_of(2)
        };
        let broken_cohorts: Vec<usize> = exercised.iter().copied().filter(is_broken).collect();
        let broken_groups: Vec<String> = broken_cohorts.iter().copied().map(cohort_group).collect();
        // Each broken cohort's siblings in the same set — admitted only once the broken one stops
        // holding the slot, and asserted below to have advanced in this same generation.
        let queued_behind: Vec<String> = broken_cohorts
            .iter()
            .flat_map(|cohort| (cohort + 1..cohort + GROUPS_PER_SET).map(cohort_group))
            .collect();
        let valid_groups: Vec<String> = exercised
            .iter()
            .copied()
            .filter(|cohort| !is_broken(cohort))
            .map(cohort_group)
            .collect();

        // Vary the fleet-wide rollout width for this wave (deterministic from the seed): [4, 8]
        // groups roll at once. The per-set cap (one rolling group per set) holds at any width, so
        // even at the SET_COUNT ceiling every set keeps its other group serving — 100% uptime;
        // a wider wave only piles more simultaneous rollouts onto the (chaos-crashed) controller.
        let width = fleet_rollout_width(seed);
        self.fleet
            .sets()
            .patch(
                FLEET_SET,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec": {"maxConcurrent": width}})),
            )
            .await?;
        println!(
            "[e2e] generation (seed {seed}, width {width}/{SET_COUNT}): BROKEN {bad_version} -> {} cohorts; VALID {good_version} -> {} cohorts (both groups of every set; each set rolls one at a time)",
            broken_groups.len(),
            valid_groups.len()
        );
        let patch_start = Instant::now();
        // The broken release's own content digest, read back from the group the deploy patched:
        // it is what each broken cohort's nodes must be found to have rejected.
        let bad_sha = deploy_release(
            &self.layout,
            &self.fleet,
            &broken_groups,
            &bad_version,
            true,
        )
        .await?;
        deploy_release(
            &self.layout,
            &self.fleet,
            &valid_groups,
            &good_version,
            false,
        )
        .await?;
        println!(
            "[e2e] control-plane patch applied in {}ms; broken release digest {bad_sha}",
            patch_start.elapsed().as_millis()
        );

        // Real disruption during the rollout: the one chaos mechanism SIGKILLs the pods of one
        // rolling cohort per set — never both groups of a set, so every set keeps a group serving
        // ([`UPTIME_MARGIN`] is the floor this leaves) — and sometimes the controller, so it
        // exercises PVC-backed recovery of an interrupted install, update, and rollback.
        let injector = self.clone();
        // Chaos still targets only the FIRST group of each set — the one the set admits first.
        // Widening it to every exercised group would let it SIGKILL the pods of a group that is
        // still serving while its sibling rolls, which is the one thing this layout guarantees
        // never happens ([`UPTIME_MARGIN`]).
        let rolling: Vec<String> = (0..COHORT_COUNT)
            .filter(|cohort| cohort.is_multiple_of(GROUPS_PER_SET))
            .map(cohort_group)
            .collect();
        tokio::spawn(async move { injector.inject_chaos(seed, rolling).await });

        let wait_start = Instant::now();
        let mut settled_broken: HashSet<String> = HashSet::new();
        let mut settled_valid: HashSet<String> = HashSet::new();
        let mut last_logged_secs = 0u64;
        let mut last_error = String::new();
        // Generous ceiling: the whole fleet pipelines a few groups at a time, and controller chaos
        // (recovering only after lease expiry) can stretch a rollout well past its uncontested
        // duration — it must still finish, just slower.
        for _ in 0..FLEET_ROLLOUT_TIMEOUT_SECS {
            // This loop polls the apiserver once a second for the whole rollout while the chaos
            // injector is deleting controller pods, so a transient list failure is not a verdict:
            // it is retried like an unsettled pass and reported only if the wait runs out.
            let fleet = match self.fleet.nodes().await {
                Ok(fleet) => {
                    last_error.clear();
                    fleet
                }
                Err(error) => {
                    last_error = error.to_string();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let mut by_group: BTreeMap<&str, Vec<&FleetNode>> = BTreeMap::new();
            for node in fleet.iter().filter(|node| is_cohort_member(node)) {
                if let Some(group) = node.selected_group.as_deref() {
                    by_group.entry(group).or_default().push(node);
                }
            }
            // Valid cohorts flip to "updated" the instant all their nodes run the new version —
            // independently, so a fast valid cohort never waits on a slow broken one.
            for group in &valid_groups {
                if settled_valid.contains(group) {
                    continue;
                }
                let done = by_group.get(group.as_str()).is_some_and(|nodes| {
                    nodes.len() == COHORT_SIZE
                        && nodes
                            .iter()
                            .all(|node| node_converged(node, good_version.as_str()))
                });
                if done {
                    settled_valid.insert(group.clone());
                    println!(
                        "[e2e] UPGRADE complete — {group} advanced to {good_version} ({}s)",
                        wait_start.elapsed().as_secs()
                    );
                }
            }
            // A broken cohort is "contained" only once every node of it is healthy BELOW the broken
            // release AND at least one of them carries the durable rejection record naming that
            // release's own bytes — the proof it attempted the release and refused it for good,
            // rather than merely never having received it.
            //
            // At least one, not all, and that is the fleet verdict working: the first node's
            // rejection is evidence enough to HALT the deployment (`maxRegressions` defaults to
            // one), and a halted body is moved to nobody else — so the cohort's remaining nodes
            // are deliberately never handed the release and can have no record of it. Requiring
            // every node to hold one would be requiring the bad release to reach every node, which
            // is precisely what the regression response exists to prevent.
            for group in &broken_groups {
                if settled_broken.contains(group) {
                    continue;
                }
                let Some(nodes) = by_group.get(group.as_str()) else {
                    continue;
                };
                let held = nodes.len() == COHORT_SIZE
                    && nodes.iter().all(|node| {
                        node.healthy
                            && node
                                .version
                                .as_deref()
                                .and_then(version_major)
                                .is_some_and(|major| major < bad_major)
                    });
                // The exec-per-node rejection read only runs once a cohort already looks rolled
                // back, so it costs one round of execs per cohort, not a poll.
                if held
                    && nodes
                        .iter()
                        .any(|node| rejected_release(&node.node, &bad_sha))
                {
                    settled_broken.insert(group.clone());
                    println!(
                        "[e2e] CONTAINED — {group} attempted {bad_version}, rejected its bytes, and \
                         holds its predecessor ({}s)",
                        wait_start.elapsed().as_secs()
                    );
                }
            }

            let elapsed = wait_start.elapsed().as_secs();
            if settled_broken.len() == broken_groups.len()
                && settled_valid.len() == valid_groups.len()
            {
                println!(
                    "[e2e] generation settled in {elapsed}s, including the {} cohorts queued behind \
                     a rejecting sibling in their own set",
                    queued_behind.len()
                );
                self.assert_halt_and_alert(&broken_cohorts, &bad_version)
                    .await?;
                return Ok(());
            }
            if elapsed >= last_logged_secs + 15 {
                last_logged_secs = elapsed;
                println!(
                    "[e2e] {}/{} cohorts settled ({} rolled back, {} advanced), {elapsed}s elapsed",
                    settled_broken.len() + settled_valid.len(),
                    exercised.len(),
                    settled_broken.len(),
                    settled_valid.len()
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // The deadlock this generation is the regression test for has ONE signature, so the timeout
        // names it: a group queued behind a rejecting sibling never advances, because the sibling's
        // rollout is still counted in flight and still holds its set's only slot.
        let wedged: Vec<&String> = queued_behind
            .iter()
            .filter(|group| !settled_valid.contains(*group))
            .collect();
        Err(format!(
            "generation did not settle within {FLEET_ROLLOUT_TIMEOUT_SECS} seconds: {} of {} \
             cohorts settled; {} of the cohorts queued behind a rejecting sibling never advanced \
             {wedged:?} — a rejecting group is holding its set's slot{}{last_error}",
            settled_broken.len() + settled_valid.len(),
            exercised.len(),
            wedged.len(),
            if last_error.is_empty() {
                ""
            } else {
                "; last error: "
            }
        )
        .into())
    }

    /// The fleet-level regression response, end to end: enough nodes independently proved the
    /// broken release bad, so every set governing one of those groups HALTS it — and the operator
    /// is told.
    ///
    /// Three records, no log scraping: the set's own `status.halted` (the verdict, with its
    /// evidence count), the group's `DeploymentHalted` condition (the one place a halt is visible
    /// for a group no set governs), and the document the control plane actually delivered to the
    /// webhook, read back from the receiver's durable record. The condition and the delivery are
    /// asserted TOGETHER because they are the two halves of the design: the condition is the
    /// durable fact and the webhook is one delivery of its transition, and a system that publishes
    /// the first while silently dropping the second is exactly the "contained but silent" failure
    /// the alerting exists to end.
    ///
    /// All three are asserted PER COHORT, and the delivery is bound to the halt beside it by the
    /// resource it names and the canonical versioned deployment identity in its evidence. Any weaker filter —
    /// "some DeploymentHalted document arrived" — is satisfied by a single delivery, so a sink
    /// that delivered one halt and dropped the other fifteen would still pass, which is precisely
    /// the silence the pairing is here to detect.
    async fn assert_halt_and_alert(
        &self,
        broken_cohorts: &[usize],
        bad_version: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The halt is a planner verdict recomputed every pass and published with the status, so it
        // is present within a reconcile or two of the rollback; the webhook delivery is bounded and
        // retried behind it. This waits for both rather than sampling once.
        let mut last = String::new();
        for _ in 0..120 {
            let mut pending = Vec::new();
            let delivered = delivered_alerts();
            let mut matched: Vec<&serde_json::Value> = Vec::new();
            for cohort in broken_cohorts {
                let group = cohort_group(*cohort);
                let set = set_name(cohort_set_index(*cohort));
                // The deployment identity the group was rolled to, spelled exactly as `deploy`
                // patched it — so this cannot pass on a halt of some other body.
                let deployment = versioned_deployment_name(&group, bad_version);
                if !halted_deployments(&set).contains(&deployment) {
                    pending.push(format!("{set}.status.halted lacks {deployment}"));
                    continue;
                }
                if condition_field(
                    &group,
                    updatec::status_contract::DEPLOYMENT_HALTED_CONDITION,
                    "status",
                )
                .as_deref()
                    != Some(updatec::status_contract::CONDITION_TRUE)
                {
                    pending.push(format!("{group}/DeploymentHalted is not True"));
                }
                // The delivery is required PER COHORT and bound to this cohort's identity: the
                // sink coalesces on `(resource, condition)`, so the halts of N broken cohorts are
                // N distinct pending documents. A filter on the condition name alone was satisfied
                // by any one of them — a drain that delivered the first and then stopped passed
                // while every other halt was silently dropped, which is the exact failure this
                // assertion is paired with the condition check to catch. The condition message
                // names the halted body (`deployment <group>-<version> is halted: …`), so the
                // evidence field is what ties a document to the halt just asserted.
                let by_set = format!("UpdateGroupSet/{set}");
                let by_group = format!("UpdateGroup/{group}");
                let found = delivered.iter().find(|alert| {
                    alert["condition"] == updatec::status_contract::DEPLOYMENT_HALTED_CONDITION
                        && alert["state"] == updatec::status_contract::CONDITION_TRUE
                        && alert["resource"]
                            .as_str()
                            .is_some_and(|name| name == by_set || name == by_group)
                        && alert["evidence"]
                            .as_str()
                            .is_some_and(|evidence| evidence.contains(&deployment))
                });
                match found {
                    Some(alert) => matched.push(alert),
                    None => pending.push(format!(
                        "no DeploymentHalted document naming {by_set} or {by_group} with \
                         {deployment} in its evidence reached the webhook receiver"
                    )),
                }
            }
            if pending.is_empty() {
                // The payload is the generic document `alerting-design.md` specifies — every field
                // present, naming the resource whose condition flipped and carrying the evidence
                // behind the verdict. A delivery that arrived shaped differently would satisfy a
                // "did anything arrive" check and be useless to a receiver.
                for alert in &matched {
                    for field in [
                        "resource",
                        "condition",
                        "state",
                        "reason",
                        "evidence",
                        "timestamp",
                    ] {
                        if !alert[field].is_string() {
                            return Err(
                                format!("the delivered alert is missing {field}: {alert}").into()
                            );
                        }
                    }
                }
                let example = matched.first().copied().unwrap_or(&serde_json::Value::Null);
                println!(
                    "[e2e] regression halt on {bad_version} is published on every affected set and \
                     group, and each of the {} halted cohort(s) has its own DeploymentHalted \
                     document at the webhook (e.g. {}: {})",
                    broken_cohorts.len(),
                    example["resource"].as_str().unwrap_or_default(),
                    example["evidence"].as_str().unwrap_or_default()
                );
                return Ok(());
            }
            last = pending.join("; ");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(format!("the regression halt never reached its records or its webhook: {last}").into())
    }

    /// Converge the whole fleet: roll `converge_major` to every cohort and wait for all of them —
    /// rolled-back and advanced alike — to reach it. A pure forward step (`converge_major` is
    /// above every version used during divergence), so it lifts the rolled-back cohorts off their
    /// predecessors and unifies the fleet.
    async fn converge(&self, converge_major: usize) -> Result<(), Box<dyn std::error::Error>> {
        let converge_version = format!("{converge_major}.0.0");
        println!("[e2e] CONVERGENCE: upgrading all {COHORT_COUNT} cohorts to {converge_version}");
        let groups: Vec<String> = (0..COHORT_COUNT).map(cohort_group).collect();
        deploy_release(&self.layout, &self.fleet, &groups, &converge_version, false).await?;

        // The budget is [`FLEET_ROLLOUT_TIMEOUT_SECS`] of *admitting* time, not wall-clock: a frozen
        // set admits no new rollout, so its time cannot count against convergence, and a freeze
        // being added or lifted resets the clock so the fleet always gets a full window once the
        // gate reopens.
        //
        // A second, ABSOLUTE ceiling bounds that pause. A set frozen for ever (a planner bug that
        // leaves a window closed) resets the admitting clock on every pass, so the budget alone can
        // never run out — the run would hang until CI's own timeout killed it with no diagnostic at
        // all. The ceiling turns that control-plane defect back into the failure below, naming the
        // sets that were still frozen.
        let hard_deadline =
            Instant::now() + Duration::from_secs(3 * FLEET_ROLLOUT_TIMEOUT_SECS as u64);
        let mut attempt = 0usize;
        let mut was_frozen = false;
        let mut last_error = String::new();
        while attempt < FLEET_ROLLOUT_TIMEOUT_SECS && Instant::now() < hard_deadline {
            let frozen_sets = self.frozen_sets().await;
            let frozen = !frozen_sets.is_empty();
            if frozen || frozen != was_frozen {
                attempt = 0;
            }
            was_frozen = frozen;
            // A transient list failure is not a verdict here either: retried like an unconverged
            // pass, reported only if the wait runs out.
            let fleet = match self.fleet.nodes().await {
                Ok(fleet) => {
                    last_error.clear();
                    fleet
                }
                Err(error) => {
                    last_error = error.to_string();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    attempt += 1;
                    continue;
                }
            };
            let cohort: Vec<&FleetNode> =
                fleet.iter().filter(|node| is_cohort_member(node)).collect();
            let on_target = cohort
                .iter()
                .filter(|node| node_converged(node, converge_version.as_str()))
                .count();
            if cohort.len() == NODE_COUNT && on_target == NODE_COUNT {
                println!("[e2e] converged all {NODE_COUNT} agents onto {converge_version}");
                return Ok(());
            }
            if attempt.is_multiple_of(15) {
                let gate = if frozen {
                    " (frozen — clock paused)"
                } else {
                    ""
                };
                println!(
                    "[e2e] convergence: {on_target}/{NODE_COUNT} agents on {converge_version}{gate}"
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            attempt += 1;
        }
        let still_frozen = self.frozen_sets().await;
        Err(format!(
            "fleet did not converge onto {converge_version} within {FLEET_ROLLOUT_TIMEOUT_SECS} \
             seconds of admitting time{}{}{}{last_error}",
            if still_frozen.is_empty() {
                String::new()
            } else {
                format!("; these sets are still frozen and admit nothing: {still_frozen:?}")
            },
            if Instant::now() >= hard_deadline {
                " (the absolute ceiling was reached, so the clock was being paused by a freeze)"
            } else {
                ""
            },
            if last_error.is_empty() {
                ""
            } else {
                "; last error: "
            }
        )
        .into())
    }

    /// The throttle sets the operator currently reports frozen (outside their rollout
    /// window/calendar), by name. While frozen no new rollout is admitted, so the convergence wait
    /// must not count that time against its budget — and when the wait fails, these are the sets
    /// that explain why. Best-effort: an API hiccup reads as nothing frozen, so a transient error
    /// can never wedge the loop.
    async fn frozen_sets(&self) -> Vec<String> {
        self.fleet
            .sets()
            .list(&Default::default())
            .await
            .map(|sets| {
                sets.into_iter()
                    .filter(|set| {
                        set.status
                            .as_ref()
                            .and_then(|status| status.frozen)
                            .unwrap_or(false)
                    })
                    .filter_map(|set| set.metadata.name)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The one chaos mechanism, fired a random 0-5s into the rollout. It abruptly SIGKILLs pods —
    /// no graceful drain — so recovery is purely from persisted, PVC-backed state: a recreated
    /// agent must resume an interrupted cold-install from its install journal, recover a
    /// mid-flight upgrade from the update journal, and relaunch the committed release through its
    /// reconciler's boot hook.
    ///
    /// Two bounded targets, so it exercises recovery without ever breaching availability:
    ///   * Fleet pods — the pods of exactly ONE rolling cohort group per set, so the set's other
    ///     group keeps serving ([`UPTIME_MARGIN`] is the floor this leaves).
    ///   * The controller — some rounds also crash the updatec operator, which reloads its
    ///     persisted admitted-deployment state and resumes the rollout where it left off.
    async fn inject_chaos(&self, seed: u64, rolling: Vec<String>) {
        let mut rng = seed ^ CHAOS_SEED_SPREAD;
        let delay = Duration::from_millis(splitmix64(&mut rng) % 5_000);
        tokio::time::sleep(delay).await;

        // Folded-in control-plane chaos: crash the controller on ~half of rounds. Recovery is
        // from persisted state + lease expiry — a real crash test of the operator.
        if splitmix64(&mut rng).is_multiple_of(2) {
            self.crash_controller().await;
        }

        // The rolling cohorts of this generation, grouped by set. An ordered map, deliberately:
        // victim selection indexes into its keys with the seeded RNG, and `HashMap` iteration
        // order varies per process — so the same seed would pick different victims on every run
        // and a reported failure could not be replayed.
        let mut by_set: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for cohort in 0..COHORT_COUNT {
            if rolling.contains(&cohort_group(cohort)) {
                by_set
                    .entry(cohort_set_index(cohort))
                    .or_default()
                    .push(cohort);
            }
        }
        let mut victims = Vec::new();
        for cohorts in by_set.values() {
            // At most one cohort group per set: pick a single group and take all of its pods,
            // leaving every other group in the set untouched.
            let cohort = cohorts[(splitmix64(&mut rng) as usize) % cohorts.len()];
            victims.extend(
                (0..COHORT_SIZE).map(|member| format!("agent-{}", cohort * COHORT_SIZE + member)),
            );
        }
        for pod in &victims {
            println!(
                "[e2e] chaos SIGKILLs pod {pod} {:.1}s into the rollout; it recovers from its retained PVC",
                delay.as_secs_f64()
            );
            // Force-delete through the kube API — the equivalent of `kubectl delete --force
            // --grace-period=0`.
            if let Err(error) = self
                .fleet
                .pods()
                .delete(
                    pod,
                    &DeleteParams {
                        grace_period_seconds: Some(0),
                        ..Default::default()
                    },
                )
                .await
            {
                println!("[e2e] chaos could not delete pod {pod}: {error}");
            }
        }
    }

    /// Abruptly crash the updatec controller (SIGKILL, no lease release), part of the one
    /// chaos mechanism. It reloads persisted state and resumes, so the rollout survives.
    async fn crash_controller(&self) {
        match self
            .fleet
            .pods()
            .delete_collection(
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..Default::default()
                },
                &ListParams::default().labels("app=updatec-controller"),
            )
            .await
        {
            Ok(_) => println!(
                "[e2e] chaos crashed the updatec controller; it reloads persisted state and resumes"
            ),
            Err(error) => println!("[e2e] chaos could not delete the controller pod: {error}"),
        }
    }
}
