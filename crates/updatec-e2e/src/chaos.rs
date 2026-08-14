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
    /// The platform the release repository publishes bundles for, as the release-server reports it.
    pub(crate) platform: String,
    /// The signed reconciler set every published release ships with, so an ordered-fallback
    /// rollback re-selects exactly these providers — app and providers roll back as one unit.
    pub(crate) provider_path: String,
    pub(crate) provider_sha: String,
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
        // Exactly ONE group per set is exercised, and it is the set's first: the set's other group
        // stays on the baseline and keeps serving ([`UPTIME_MARGIN`]). This is not a pacing
        // preference — a cohort that rolls back never reports the identity it was assigned, so its
        // group stays "rolling" in the operator's view and holds its set's single slot. Queueing a
        // second group behind it in the same set would wait forever on a rollout the control plane
        // will never admit.
        let exercised: Vec<usize> = (0..COHORT_COUNT)
            .filter(|cohort| cohort.is_multiple_of(GROUPS_PER_SET))
            .collect();
        let broken_groups: Vec<String> = exercised
            .iter()
            .filter(|cohort| cohort_set_index(**cohort).is_multiple_of(2))
            .map(|cohort| cohort_group(*cohort))
            .collect();
        let valid_groups: Vec<String> = exercised
            .iter()
            .filter(|cohort| !cohort_set_index(**cohort).is_multiple_of(2))
            .map(|cohort| cohort_group(*cohort))
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
            "[e2e] generation (seed {seed}, width {width}/{SET_COUNT}): BROKEN {bad_version} -> {} cohorts; VALID {good_version} -> {} cohorts (one group per set; the others keep serving)",
            broken_groups.len(),
            valid_groups.len()
        );
        let patch_start = Instant::now();
        // The broken release's own content digest, read back from the group the deploy patched:
        // it is what each broken cohort's nodes must be found to have rejected.
        let bad_sha = self.deploy(&broken_groups, &bad_version, true).await?;
        self.deploy(&valid_groups, &good_version, false).await?;
        println!(
            "[e2e] control-plane patch applied in {}ms; broken release digest {bad_sha}",
            patch_start.elapsed().as_millis()
        );

        // Real disruption during the rollout: the one chaos mechanism SIGKILLs the pods of one
        // rolling cohort per set — never both groups of a set, so every set keeps a group serving
        // ([`UPTIME_MARGIN`] is the floor this leaves) — and sometimes the controller, so it
        // exercises PVC-backed recovery of an interrupted install, update, and rollback.
        let injector = self.clone();
        let rolling: Vec<String> = broken_groups.iter().chain(&valid_groups).cloned().collect();
        tokio::spawn(async move { injector.inject_chaos(seed, rolling).await });

        let wait_start = Instant::now();
        let mut settled_broken: HashSet<String> = HashSet::new();
        let mut settled_valid: HashSet<String> = HashSet::new();
        let mut last_logged_secs = 0u64;
        // Generous ceiling: the whole fleet pipelines a few groups at a time, and controller chaos
        // (recovering only after lease expiry) can stretch a rollout well past its uncontested
        // duration — it must still finish, just slower.
        for _ in 0..FLEET_ROLLOUT_TIMEOUT_SECS {
            let fleet = self.fleet.nodes().await?;
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
            // Broken cohorts flip to "rollback complete" only once every node is healthy BELOW the
            // broken release and carries the rejection record naming that release's bytes: the
            // durable proof it attempted the release and refused it, not merely that it never
            // arrived.
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
                        .all(|node| rejected_release(&node.node, &bad_sha))
                {
                    settled_broken.insert(group.clone());
                    println!(
                        "[e2e] ROLLBACK complete — {group} rejected {bad_version} and holds its predecessor ({}s)",
                        wait_start.elapsed().as_secs()
                    );
                }
            }

            let elapsed = wait_start.elapsed().as_secs();
            if settled_broken.len() == broken_groups.len()
                && settled_valid.len() == valid_groups.len()
            {
                println!("[e2e] generation settled in {elapsed}s");
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
        Err(format!(
            "generation did not settle within {FLEET_ROLLOUT_TIMEOUT_SECS} seconds: {} of {} cohorts settled",
            settled_broken.len() + settled_valid.len(),
            exercised.len()
        )
        .into())
    }

    /// Converge the whole fleet: roll `converge_major` to every cohort and wait for all of them —
    /// rolled-back and advanced alike — to reach it. A pure forward step (`converge_major` is
    /// above every version used during divergence), so it lifts the rolled-back cohorts off their
    /// predecessors and unifies the fleet.
    async fn converge(&self, converge_major: usize) -> Result<(), Box<dyn std::error::Error>> {
        let converge_version = format!("{converge_major}.0.0");
        println!("[e2e] CONVERGENCE: upgrading all {COHORT_COUNT} cohorts to {converge_version}");
        let groups: Vec<String> = (0..COHORT_COUNT).map(cohort_group).collect();
        self.deploy(&groups, &converge_version, false).await?;

        // The budget is [`FLEET_ROLLOUT_TIMEOUT_SECS`] of *admitting* time, not wall-clock: a frozen
        // set admits no new rollout, so its time cannot count against convergence, and a freeze
        // being added or lifted resets the clock so the fleet always gets a full window once the
        // gate reopens.
        let mut attempt = 0usize;
        let mut was_frozen = false;
        while attempt < FLEET_ROLLOUT_TIMEOUT_SECS {
            let frozen = self.any_set_frozen().await;
            if frozen || frozen != was_frozen {
                attempt = 0;
            }
            was_frozen = frozen;
            let fleet = self.fleet.nodes().await?;
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
        Err(format!(
            "fleet did not converge onto {converge_version} within {FLEET_ROLLOUT_TIMEOUT_SECS} seconds"
        )
        .into())
    }

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
    async fn deploy(
        &self,
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
        let (platform, provider_path, provider_sha) =
            (&self.platform, &self.provider_path, &self.provider_sha);
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
            self.fleet
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

    /// Whether the operator currently has any throttle set frozen (a set outside its rollout
    /// window/calendar). While frozen no new rollout is admitted, so the convergence wait must
    /// not count that time against its budget. Best-effort: an API hiccup reads as not-frozen so
    /// a transient error can never wedge the loop.
    async fn any_set_frozen(&self) -> bool {
        self.fleet
            .sets()
            .list(&Default::default())
            .await
            .map(|sets| {
                sets.into_iter()
                    .any(|set| set.status.and_then(|status| status.frozen).unwrap_or(false))
            })
            .unwrap_or(false)
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
