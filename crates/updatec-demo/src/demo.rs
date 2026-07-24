use crate::*;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams};
use kube::{Client, ResourceExt};
use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Clone)]
pub(crate) struct Demo {
    pub(crate) application_url: String,
    pub(crate) release: ReleaseRequest,
    pub(crate) publisher: KubernetesPublisher,
    pub(crate) http: reqwest::Client,
    pub(crate) chaos: Arc<Mutex<ChaosState>>,
    pub(crate) chaos_task: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    /// `DEMO_DISABLE_CHAOS`: when set, skip the injected disruption — no pod SIGKILLs, no
    /// controller crash. The diverge/converge rollouts still run; only the chaos injection is
    /// suppressed, for a calm, predictable demo. Defaults to false (chaos on).
    pub(crate) chaos_disabled: bool,
    /// One rolling outcome window per set — each set has its own load balancer, so the UI
    /// shows availability holding (or burning budget) independently per box.
    pub(crate) load: Arc<Vec<StdMutex<LoadWindow>>>,
    /// Each set's load balancer view of its ready endpoints (node names), refreshed in the
    /// background so per-set workers route only to serving pods in their own set.
    pub(crate) ready: Arc<Vec<StdMutex<Vec<String>>>>,
    /// Per-set latch: false until the set first reaches a full, healthy pool for
    /// [`LOAD_STEADY_GRACE`], then true forever. Workers neither send nor record until it
    /// flips, so availability reflects steady-state service, not baseline warm-up.
    pub(crate) counting: Arc<Vec<AtomicBool>>,
    /// Per-node instant readyz first started failing, for the UI's readiness debounce:
    /// at 1s polling a single missed probe shouldn't flip a node OUT, so the UI only
    /// believes OUT after readyz has failed continuously for a grace period. The
    /// generation-settle logic uses the raw signal, not this.
    pub(crate) readyz_failing_since: Arc<Mutex<std::collections::HashMap<String, Instant>>>,
    /// Fleet nodes (pod names) seen OUT of the load balancer — readiness withdrawn — at least
    /// once since the current generation began. Filled by a continuous Kubernetes *watch* on
    /// pod readiness ([`spawn_readiness_watcher`]), not a periodic poll, so a broken cohort's
    /// drain edge is recorded even when it is brief or the settle loop's own probe is busy
    /// elsewhere. Reset at each generation start; the generation-settle reads it as the durable
    /// proof a broken cohort actually *attempted* the bad release and drained — the signal that
    /// separates a genuine rollback from a cohort still sitting untouched below the bad version.
    pub(crate) left_lb: Arc<StdMutex<std::collections::HashSet<String>>>,
    /// Live load-balancer membership per fleet node (pod name → currently `Ready`), maintained
    /// by the same readiness watch ([`spawn_readiness_watcher`]). A fleet/Magnolia pod's native
    /// readinessProbe drives the per-set Service EndpointSlices, so its `Ready` condition *is*
    /// whether it is in the pool — reading it from the watch stream means the UI's IN/OUT and the
    /// synthetic load balancer's endpoint set reflect the very signal Kubernetes routes on, with
    /// no per-node `readyz` curl storm and no poll that can miss a transition. A node absent from
    /// the map (not yet observed, or not pod-backed like the unimplemented manual VM) reads OUT.
    pub(crate) readiness: Arc<StdMutex<std::collections::HashMap<String, bool>>>,
    /// Instant of the last successful readiness-watch event or relist — the watch's liveness
    /// heartbeat, stamped by [`spawn_readiness_watcher`] on every observed transition. Once it
    /// ages past [`READINESS_WATCH_STALE`] the readiness map is no longer authoritative (a
    /// stalled or reconnecting watch froze it), so [`Demo::fleet`] and [`Demo::ready_endpoints`]
    /// fail closed and treat every node as OUT rather than trusting stale membership.
    pub(crate) readiness_fresh_at: Arc<StdMutex<Instant>>,
}

impl Demo {
    pub(crate) async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let application_path = required("DEMO_APPLICATION_PATH")?;
        let application_sha256 = required("DEMO_APPLICATION_SHA256")?;
        let provider_path = required("DEMO_PROVIDER_PATH")?;
        let provider_sha256 = required("DEMO_PROVIDER_SHA256")?;
        let patch = serde_json::json!({
            "spec": {
                "defaultDeployment": {
                    "name": "default",
                    "application": {
                        "path": application_path,
                        "sha256": application_sha256
                    },
                    "providerSet": {
                        "path": provider_path,
                        "sha256": provider_sha256
                    }
                }
            }
        });
        let release = ReleaseRequest::green();
        Ok(Self {
            application_url: env::var("DEMO_APPLICATION_URL")
                .unwrap_or_else(|_| "http://agent-4.agents:8080".into()),
            release,
            publisher: KubernetesPublisher {
                namespace: env::var("DEMO_NAMESPACE").unwrap_or_else(|_| "updated-system".into()),
                repository: env::var("DEMO_REPOSITORY").unwrap_or_else(|_| "default".into()),
                patch,
                client: Client::try_default().await?,
            },
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()?,
            chaos: Arc::new(Mutex::new(ChaosState::default())),
            chaos_task: Arc::new(Mutex::new(None)),
            chaos_disabled: matches!(
                env::var("DEMO_DISABLE_CHAOS")
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            ),
            load: Arc::new(
                (0..DEMO_SET_COUNT)
                    .map(|_| StdMutex::new(LoadWindow::default()))
                    .collect(),
            ),
            ready: Arc::new(
                (0..DEMO_SET_COUNT)
                    .map(|_| StdMutex::new(Vec::new()))
                    .collect(),
            ),
            counting: Arc::new(
                (0..DEMO_SET_COUNT)
                    .map(|_| AtomicBool::new(false))
                    .collect(),
            ),
            readyz_failing_since: Arc::new(Mutex::new(std::collections::HashMap::new())),
            left_lb: Arc::new(StdMutex::new(std::collections::HashSet::new())),
            readiness: Arc::new(StdMutex::new(std::collections::HashMap::new())),
            readiness_fresh_at: Arc::new(StdMutex::new(Instant::now())),
        })
    }

    pub(crate) async fn apply(
        &self,
        requested: &ReleaseRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if requested != &self.release {
            return Err("release declaration does not match the advertised signed target".into());
        }
        self.publisher.publish(requested).await
    }

    pub(crate) async fn version(&self) -> Result<String, reqwest::Error> {
        self.http
            .get(format!("{}/version", self.application_url))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
    }

    pub(crate) async fn fleet(&self) -> Result<Vec<FleetNode>, Box<dyn std::error::Error>> {
        let agents = self.publisher.agents();
        // Load-balancer membership comes from the readiness watch, not a per-node curl: a pod's
        // native readinessProbe is what the per-set Service EndpointSlices route on, so its last
        // observed `Ready` condition is authoritative and free of a poll's blind spots — *as long
        // as the watch is live*. A watch stalled past [`READINESS_WATCH_STALE`] froze the map, so
        // it is no longer authoritative: fail closed and read every node OUT rather than trust a
        // stale IN (which could hide a real drain or forge a premature settle).
        let stale = self.readiness_is_stale();
        let readiness = self.readiness.lock().unwrap().clone();
        let mut nodes = Vec::new();
        for agent in agents.list(&Default::default()).await? {
            let Some(node) = agent.spec.labels.get("demo.updated.dev/node").cloned() else {
                continue;
            };
            let kind = agent.spec.labels.get("demo.updated.dev/kind").cloned();
            let resource = agent.name_any();
            // Running version and health come straight from the control plane — the operator
            // publishes each node's last rollout report onto its UpdateAgent status. The demo
            // never probes the managed app for a version, so a Magnolia node (which speaks no
            // /version endpoint) is read exactly like a sample-app node.
            let (selected_group, version, healthy) = agent
                .status
                .map(|status| {
                    (
                        status.selected_group,
                        status.reported_version,
                        status.reported_ready.unwrap_or(false),
                    )
                })
                .unwrap_or((None, None, false));
            // Absent from the map (never observed, or not pod-backed like the manual VM) reads
            // OUT — fail closed, exactly as a load balancer treats an endpoint it can't confirm.
            // A stalled watch forces every node OUT for the same reason: unconfirmed is not-ready.
            let in_load_balancer = !stale && readiness.get(&node).copied().unwrap_or(false);
            nodes.push(FleetNode {
                node,
                resource,
                selected_group,
                version,
                kind,
                healthy,
                in_load_balancer,
                // The watch carries no probe timing; keep the field for the UI, zeroed, and note
                // an OUT node's source so a tooltip still distinguishes it from a slow probe.
                readyz_probe_millis: 0,
                probe_note: (!in_load_balancer).then(|| {
                    if stale {
                        "readiness unknown (watch stalled) — failing closed".to_string()
                    } else {
                        "readiness withdrawn (watch)".to_string()
                    }
                }),
            });
        }
        nodes.sort_by(|left, right| left.node.cmp(&right.node));
        Ok(nodes)
    }

    /// The load balancer's health check: which fleet endpoints are ready to receive traffic
    /// right now, read straight from the readiness watch's live membership map — the same signal
    /// the per-set Service EndpointSlices route on, so the synthetic load balancer and Kubernetes
    /// always agree on the pool. No API list or probe, so it is cheap enough to poll often.
    pub(crate) async fn ready_endpoints(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        // A stalled watch froze the membership map: serve no endpoints rather than route on stale
        // readiness (fail closed), the same rule [`Self::fleet`] applies.
        if self.readiness_is_stale() {
            return Ok(Vec::new());
        }
        let ready = self
            .readiness
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, ready)| **ready)
            .map(|(node, _)| node.clone())
            .collect();
        Ok(ready)
    }

    /// Whether the readiness watch has gone longer than [`READINESS_WATCH_STALE`] without a
    /// successful event or relist. When true the frozen readiness map is no longer authoritative,
    /// so membership reads fail closed.
    fn readiness_is_stale(&self) -> bool {
        self.readiness_fresh_at.lock().unwrap().elapsed() > READINESS_WATCH_STALE
    }

    /// The current golden signals per set, plus a fleet-wide aggregate for the top panel.
    pub(crate) fn golden(&self) -> GoldenReport {
        let now = Instant::now();
        let mut sets = Vec::with_capacity(DEMO_SET_COUNT);
        let mut all = Vec::new();
        let mut ready_total = 0;
        for set in 0..DEMO_SET_COUNT {
            let ready = self.ready[set].lock().unwrap().len();
            ready_total += ready;
            let window = self.load[set].lock().unwrap();
            all.extend(window.samples.iter().cloned());
            sets.push(SetSignals {
                set: set_name(set),
                signals: GoldenSignals::from_window(&window, ready, now),
            });
        }
        let fleet_window = LoadWindow {
            samples: all.into(),
        };
        let fleet = GoldenSignals::from_window(&fleet_window, ready_total, now);
        GoldenReport { fleet, sets }
    }

    /// The fleet snapshot the UI renders: the raw probe from [`Self::fleet`] with a
    /// readiness *debounce* applied. A node is only reported OUT once its readyz has
    /// failed continuously for [`READYZ_DEBOUNCE`]; a single missed probe at 1s polling
    /// keeps it IN (annotated as debounced). Generation-settle uses raw `fleet()`, so
    /// this smoothing never affects correctness — only what the human sees.
    pub(crate) async fn fleet_for_ui(&self) -> Result<Vec<FleetNode>, Box<dyn std::error::Error>> {
        const READYZ_DEBOUNCE: Duration = Duration::from_secs(2);
        let mut nodes = self.fleet().await?;
        let now = Instant::now();
        let mut failing = self.readyz_failing_since.lock().await;
        for node in &mut nodes {
            if node.in_load_balancer {
                failing.remove(&node.node);
                continue;
            }
            let since = *failing.entry(node.node.clone()).or_insert(now);
            let elapsed = now.saturating_duration_since(since);
            if elapsed < READYZ_DEBOUNCE {
                node.in_load_balancer = true;
                let debounced = format!(
                    "readyz failing {}ms (debounced, still IN)",
                    elapsed.as_millis()
                );
                node.probe_note = Some(match node.probe_note.take() {
                    Some(existing) => format!("{existing}; {debounced}"),
                    None => debounced,
                });
            }
        }
        let present: std::collections::HashSet<&String> = nodes.iter().map(|n| &n.node).collect();
        failing.retain(|node, _| present.contains(node));
        Ok(nodes)
    }

    pub(crate) async fn groups(&self) -> Result<Vec<GroupView>, Box<dyn std::error::Error>> {
        let groups = self.publisher.groups();
        let agents = self.publisher.agents();
        // Membership comes straight from the agent resources — no HTTP probes — so
        // /groups is a cheap pair of API reads the UI can poll every second without the
        // fleet snapshot's per-agent probe cost.
        let mut members: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for agent in agents.list(&Default::default()).await? {
            let Some(node) = agent.spec.labels.get("demo.updated.dev/node").cloned() else {
                continue;
            };
            if let Some(group) = agent.status.and_then(|status| status.selected_group) {
                members.entry(group).or_default().push(node);
            }
        }
        let mut views = groups
            .list(&Default::default())
            .await?
            .into_iter()
            .filter(|group| !group.name_any().starts_with("overlapping-"))
            .map(|group| {
                let name = group.name_any();
                let set = group.labels().get(SET_LABEL).cloned().unwrap_or_default();
                let selector = group
                    .spec
                    .selector
                    .match_labels
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let desired_version = group
                    .spec
                    .deployment
                    .application
                    .path
                    .split('/')
                    .find(|segment| segment.ends_with(".0.0"))
                    .unwrap_or("unknown")
                    .to_owned();
                let mut selected_nodes = members.get(&name).cloned().unwrap_or_default();
                selected_nodes.sort();
                GroupView {
                    name,
                    set,
                    selector,
                    desired_version,
                    selected_nodes,
                }
            })
            .collect::<Vec<_>>();
        views.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(views)
    }

    /// Start (or, mid-epoch, resume) the convergence chaos. `epochs` bounds how many
    /// full diverge-then-converge cycles to run; `None` runs forever. Baseline is the
    /// version the fleet currently sits on, and `loop_number` is preserved so a
    /// restart continues the current epoch rather than restarting it.
    pub(crate) async fn start_chaos(
        &self,
        seed: u64,
        epochs: Option<usize>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(task) = self.chaos_task.lock().await.take() {
            task.abort();
        }
        // Diverge from the fleet's actual baseline. Never guess: if no node reports a
        // version yet the fleet is not at baseline, and defaulting low would roll
        // downgrades every agent rejects. Wait for a real version, then take the max.
        let mut baseline_major = None;
        for _ in 0..60 {
            baseline_major = self
                .fleet()
                .await?
                .iter()
                .filter_map(|node| node.version.as_deref())
                .filter_map(version_major)
                .max();
            if baseline_major.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let baseline_major = baseline_major
            .ok_or("cannot start chaos: the fleet reports no version yet (not at baseline)")?;
        let first_loop = {
            let mut state = self.chaos.lock().await;
            let verb = if state.loop_number == 0 {
                "starting"
            } else {
                "resuming"
            };
            state.running = true;
            state.complete = false;
            state.seed = seed;
            state.error = None;
            state.active_broken.clear();
            state.active_valid.clear();
            state.converging = false;
            state.events.push(format!(
                "seed {seed}: {verb} convergence chaos from {baseline_major}.0.0"
            ));
            if self.chaos_disabled {
                state.events.push(
                    "pod-kill chaos disabled (DEMO_DISABLE_CHAOS): rolling without injected disruption".into(),
                );
            }
            trim_events(&mut state.events);
            state.loop_number
        };
        let demo = self.clone();
        let task = tokio::spawn(async move {
            let result = demo
                .run_chaos(seed, epochs, first_loop, baseline_major)
                .await
                .map_err(|error| error.to_string());
            if let Err(error) = result {
                let mut state = demo.chaos.lock().await;
                state.running = false;
                state.error = Some(error.clone());
                state.events.push(format!("FAILED: {error}"));
                trim_events(&mut state.events);
            }
        });
        *self.chaos_task.lock().await = Some(task.abort_handle());
        Ok(())
    }

    /// Drive convergence epochs until `epochs` complete (or forever when `None`).
    ///
    /// Each epoch *diverges* the fleet one generation at a time — every generation
    /// rolls a broken release to one fresh cohort and a valid release to another —
    /// until all sixteen cohorts have been exercised, then *converges* them onto a
    /// single new version `100 * epoch + 1`. That converged version is the next
    /// epoch's baseline and the loop counter jumps to it, so both versions and the
    /// loop number only ever increase. Restarting mid-epoch (the "skip" button)
    /// resumes from the preserved per-cohort state rather than re-exercising cohorts.
    pub(crate) async fn run_chaos(
        &self,
        mut seed: u64,
        epochs: Option<usize>,
        first_loop: usize,
        baseline_major: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut loop_number = first_loop;
        let mut baseline_major = baseline_major;
        let mut completed_epochs = 0usize;
        loop {
            let epoch = loop_number.saturating_sub(1) / 100 + 1;
            let converge_major = epoch * 100 + 1;
            {
                let mut state = self.chaos.lock().await;
                // Only a genuinely new epoch clears per-cohort progress; a mid-epoch
                // restart keeps it so divergence resumes where it left off.
                if state.epoch != epoch {
                    state.epoch = epoch;
                    state.rolled_back_groups.clear();
                    state.updated_groups.clear();
                    state.active_broken.clear();
                    state.active_valid.clear();
                    state.converging = false;
                    state.completed_nodes = 0;
                    state.events.push(format!(
                        "epoch {epoch}: diverging the fleet from {baseline_major}.0.0 toward convergence on {converge_major}.0.0"
                    ));
                    trim_events(&mut state.events);
                }
            }
            let mut generation_major = baseline_major;
            while let Some(assignments) = self.select_generation().await {
                let bad_major = generation_major + 1;
                let good_major = generation_major + 2;
                loop_number += 1;
                {
                    let mut state = self.chaos.lock().await;
                    state.seed = seed;
                    state.loop_number = loop_number;
                    state.bad_version = format!("{bad_major}.0.0");
                    state.good_version = format!("{good_major}.0.0");
                }
                self.run_generation(seed, &assignments, bad_major, good_major)
                    .await?;
                generation_major = good_major;
                seed = seed.wrapping_add(1);
            }
            self.converge_epoch(converge_major).await?;
            baseline_major = converge_major;
            loop_number = converge_major;
            completed_epochs += 1;
            {
                let mut state = self.chaos.lock().await;
                state.loop_number = loop_number;
                state.completed_epochs = completed_epochs;
                state.good_version = format!("{converge_major}.0.0");
                state.events.push(format!(
                    "epoch {epoch}: converged all {DEMO_COHORT_COUNT} cohorts onto {converge_major}.0.0"
                ));
                trim_events(&mut state.events);
            }
            if epochs.is_some_and(|limit| completed_epochs >= limit) {
                let mut state = self.chaos.lock().await;
                state.running = false;
                state.complete = true;
                return Ok(());
            }
        }
    }

    /// The whole epoch's rollout in one batch: every still-baseline cohort with its role
    /// `(cohort, is_broken)`, or `None` once all have been exercised and it is time to
    /// converge. Roles alternate by set — even sets take the broken release (roll back),
    /// odd sets the valid one (roll forward) — so the pipeline always shows a mix in flight.
    ///
    /// The demo patches them all at once; the control plane's fleet set does the pacing,
    /// keeping [`DEMO_FLEET_CONCURRENCY`] rolling at a time in set order and admitting the
    /// next the instant one settles. There is no per-generation batching here — the whole
    /// fleet is queued and pipelined.
    pub(crate) async fn select_generation(&self) -> Option<Vec<(usize, bool)>> {
        let state = self.chaos.lock().await;
        let assignments: Vec<(usize, bool)> = (0..DEMO_COHORT_COUNT)
            .filter(|&cohort| {
                let group = cohort_group(cohort);
                !state.rolled_back_groups.contains(&group) && !state.updated_groups.contains(&group)
            })
            .map(|cohort| (cohort, cohort_set_index(cohort).is_multiple_of(2)))
            .collect();
        (!assignments.is_empty()).then_some(assignments)
    }

    /// Run one generation: roll broken `bad_major` to the broken set's cohorts and valid
    /// `good_major` to the valid set's cohorts (two sets in all, throttled per set),
    /// inject stateless pod-kill chaos into every exercised cohort, then wait for the
    /// fleet to settle. Settled means: each broken cohort is healthy on a release
    /// *below* the broken one (live nodes hold their predecessor; killed cold nodes
    /// descend through signed ordered fallback), each valid cohort is healthy on the
    /// new version, and every other cohort is untouched.
    pub(crate) async fn run_generation(
        &self,
        seed: u64,
        assignments: &[(usize, bool)],
        bad_major: usize,
        good_major: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let good_version = format!("{good_major}.0.0");
        let bad_version = format!("{bad_major}.0.0");
        let broken_groups: Vec<String> = assignments
            .iter()
            .filter(|(_, broken)| *broken)
            .map(|(cohort, _)| cohort_group(*cohort))
            .collect();
        let valid_groups: Vec<String> = assignments
            .iter()
            .filter(|(_, broken)| !*broken)
            .map(|(cohort, _)| cohort_group(*cohort))
            .collect();

        let broken_source = if broken_groups.is_empty() {
            None
        } else {
            Some(self.build_release_source(bad_major, true)?)
        };
        let valid_source = if valid_groups.is_empty() {
            None
        } else {
            Some(self.build_release_source(good_major, false)?)
        };
        // Vary the fleet-wide rollout width for this wave (deterministic from the seed): [4, 8]
        // groups roll at once. The per-set cap (one rolling group per set) holds at any width, so
        // even at the DEMO_SET_COUNT ceiling every set keeps its other group serving — 100% uptime;
        // a wider wave only piles more simultaneous rollouts onto the (chaos-crashed) controller.
        let width = fleet_rollout_width(seed);
        self.publisher
            .sets()
            .patch(
                DEMO_FLEET_SET,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec": {"maxConcurrent": width}})),
            )
            .await?;
        {
            let mut state = self.chaos.lock().await;
            state.active_broken.clone_from(&broken_groups);
            state.active_valid.clone_from(&valid_groups);
            state.events.push(format!(
                "gen (seed {seed}, width {width}/{DEMO_SET_COUNT}): BROKEN {bad_version} -> [{}]; VALID {good_version} -> [{}]",
                if broken_groups.is_empty() {
                    "none".into()
                } else {
                    broken_groups.join(", ")
                },
                if valid_groups.is_empty() {
                    "none".into()
                } else {
                    valid_groups.join(", ")
                }
            ));
            trim_events(&mut state.events);
        }
        let exercised = (broken_groups.len() + valid_groups.len()) * DEMO_COHORT_SIZE;
        // Fresh drain evidence for this generation: forget departures the readiness watch
        // recorded during the previous generation or the convergence between them, so a broken
        // cohort must leave the load balancer *this* generation to count as having attempted the
        // bad release.
        self.left_lb.lock().unwrap().clear();
        let patch_start = Instant::now();
        if let Some(source) = &broken_source {
            for group in &broken_groups {
                self.deploy_group(group, &bad_version, source).await?;
            }
        }
        if let Some(source) = &valid_source {
            for group in &valid_groups {
                self.deploy_group(group, &good_version, source).await?;
            }
        }
        self.event(format!(
            "gen (seed {seed}): control-plane patch applied in {}ms; waiting for {exercised} agents to react",
            patch_start.elapsed().as_millis()
        ))
        .await;

        // Real disruption during the rollout: the one chaos mechanism SIGKILLs already-draining
        // pods (bounded to one group per set) and sometimes the controller, so it exercises
        // PVC-backed recovery without ever dropping a set below its serving floor.
        if !self.chaos_disabled {
            let chaos_demo = self.clone();
            tokio::spawn(async move {
                chaos_demo.inject_chaos(seed).await;
            });
        }

        // Telemetry: closures naming each exercised node's target/membership so the wait
        // loop can report first-reaction latency and per-3s progress — this is where the
        // seconds of a rollout actually go, made visible in the events log.
        let node_on_target = |node: &FleetNode| match node.selected_group.as_deref() {
            Some(group) if broken_groups.iter().any(|g| g == group) => {
                node.healthy
                    && node.in_load_balancer
                    && node
                        .version
                        .as_deref()
                        .and_then(version_major)
                        .is_some_and(|major| major < bad_major)
            }
            Some(group) if valid_groups.iter().any(|g| g == group) => {
                node.healthy
                    && node.in_load_balancer
                    && node.version.as_deref() == Some(good_version.as_str())
            }
            _ => true,
        };
        let is_exercised = |node: &FleetNode| {
            node.selected_group.as_deref().is_some_and(|group| {
                broken_groups.iter().any(|g| g == group) || valid_groups.iter().any(|g| g == group)
            })
        };

        use std::collections::{HashMap, HashSet};
        let wait_start = Instant::now();
        // Which broken cohorts have attempted the bad release and drained comes from the
        // readiness watch's durable [`Demo::left_lb`] set, not this loop's own probe — a brief
        // or already-past drain still counts, which is exactly what separates a genuine rollback
        // from a cohort still sitting untouched below the bad version.
        let mut settled_broken: HashSet<String> = HashSet::new();
        let mut settled_valid: HashSet<String> = HashSet::new();
        let mut reacted = false;
        let mut last_logged_secs = 0u64;
        // Generous ceiling: the whole fleet pipelines 4-at-a-time, and controller chaos
        // (storm runs kill it every ~10s, recovering only after lease expiry) can stretch a
        // rollout well past its uncontested duration — it must still finish, just slower.
        for _ in 0..DEMO_SETTLE_TIMEOUT_SECS {
            let fleet = self.fleet().await?;
            let mut by_group: HashMap<&str, Vec<&FleetNode>> = HashMap::new();
            for node in fleet.iter().filter(|node| is_exercised(node)) {
                if let Some(group) = node.selected_group.as_deref() {
                    by_group.entry(group).or_default().push(node);
                }
            }
            // Valid cohorts flip to "updated" the instant all their nodes run the new
            // version and are back in the load balancer — independently, so a fast valid
            // cohort never waits on a slow broken one (and never bleeds into next gen).
            for group in &valid_groups {
                if settled_valid.contains(group) {
                    continue;
                }
                let nodes = by_group.get(group.as_str());
                let done = nodes.is_some_and(|nodes| {
                    nodes.len() == DEMO_COHORT_SIZE
                        && nodes.iter().all(|node| {
                            node.healthy
                                && node.in_load_balancer
                                && node.version.as_deref() == Some(good_version.as_str())
                        })
                });
                if done {
                    settled_valid.insert(group.clone());
                    let mut state = self.chaos.lock().await;
                    state.active_valid.retain(|active| active != group);
                    if !state.updated_groups.contains(group) {
                        state.updated_groups.push(group.clone());
                    }
                    state.completed_nodes =
                        state.rolled_back_groups.len() + state.updated_groups.len();
                    state.events.push(format!(
                        "gen (seed {seed}): UPGRADE complete — {group} advanced to {good_version} ({}s)",
                        wait_start.elapsed().as_secs()
                    ));
                    trim_events(&mut state.events);
                }
            }
            // Broken cohorts flip to "rollback complete" only once every node has attempted
            // the bad release (seen out of the LB by the readiness watch) AND is now healthy,
            // back in the LB, below it.
            for group in &broken_groups {
                if settled_broken.contains(group) {
                    continue;
                }
                // Attempted-and-drained: every one of the cohort's nodes was seen out of the
                // load balancer this generation by the readiness watch. Durable, so a drain that
                // has already ended still proves the attempt.
                let attempted = {
                    let left = self.left_lb.lock().unwrap();
                    by_group.get(group.as_str()).is_some_and(|nodes| {
                        nodes.len() == DEMO_COHORT_SIZE
                            && nodes.iter().all(|node| left.contains(&node.node))
                    })
                };
                let held = by_group.get(group.as_str()).is_some_and(|nodes| {
                    nodes.len() == DEMO_COHORT_SIZE
                        && nodes.iter().all(|node| {
                            node.healthy
                                && node.in_load_balancer
                                && node
                                    .version
                                    .as_deref()
                                    .and_then(version_major)
                                    .is_some_and(|major| major < bad_major)
                        })
                });
                if attempted && held {
                    settled_broken.insert(group.clone());
                    let mut state = self.chaos.lock().await;
                    state.active_broken.retain(|active| active != group);
                    if !state.rolled_back_groups.contains(group) {
                        state.rolled_back_groups.push(group.clone());
                    }
                    state.completed_nodes =
                        state.rolled_back_groups.len() + state.updated_groups.len();
                    state.events.push(format!(
                        "gen (seed {seed}): ROLLBACK complete — {group} held below broken {bad_version} ({}s)",
                        wait_start.elapsed().as_secs()
                    ));
                    trim_events(&mut state.events);
                }
            }

            let on_target = fleet
                .iter()
                .filter(|node| is_exercised(node) && node_on_target(node))
                .count();
            let draining = fleet
                .iter()
                .filter(|node| is_exercised(node) && !node.in_load_balancer)
                .count();
            let elapsed = wait_start.elapsed().as_secs();
            if !reacted && draining > 0 {
                reacted = true;
                self.event(format!(
                    "gen (seed {seed}): first agent left the load balancer after {elapsed}s"
                ))
                .await;
            }
            let all_settled = settled_broken.len() == broken_groups.len()
                && settled_valid.len() == valid_groups.len();
            if all_settled {
                self.event(format!(
                    "gen (seed {seed}): generation settled in {elapsed}s"
                ))
                .await;
                return Ok(());
            }
            if elapsed >= last_logged_secs + 3 {
                last_logged_secs = elapsed;
                self.event(format!(
                    "gen (seed {seed}): {on_target}/{exercised} agents on target, {draining} draining, {elapsed}s elapsed"
                ))
                .await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(format!(
            "generation (broken [{}], valid [{}]) did not settle within {DEMO_SETTLE_TIMEOUT_SECS} seconds",
            broken_groups.join(", "),
            valid_groups.join(", ")
        )
        .into())
    }

    /// Converge the whole fleet: roll `converge_major` to every cohort and wait for
    /// all sixteen — rolled-back and ready alike — to reach it. A pure forward step
    /// (`converge_major` is above every version used during divergence), so it lifts
    /// the failed cohorts off their predecessors and unifies the fleet.
    pub(crate) async fn converge_epoch(
        &self,
        converge_major: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let converge_version = format!("{converge_major}.0.0");
        {
            let mut state = self.chaos.lock().await;
            // Convergence is a pure forward UPGRADE for every cohort — no cohort is
            // broken here. Clear the divergence roles so nothing renders as broken or
            // rolled-back while the fleet climbs to the new baseline.
            state.active_broken.clear();
            state.active_valid.clear();
            state.converging = true;
            state.good_version = converge_version.clone();
            state.events.push(format!(
                "CONVERGENCE: upgrading all {DEMO_COHORT_COUNT} cohorts to {converge_version} (the next epoch's baseline)"
            ));
            trim_events(&mut state.events);
        }
        let source = self.build_release_source(converge_major, false)?;
        for index in 0..DEMO_COHORT_COUNT {
            self.deploy_group(&cohort_group(index), &converge_version, &source)
                .await?;
        }

        let mut converged = false;
        // Budget is 240s of *admitting* time, not wall-clock. A frozen set admits no new
        // rollout, so its time cannot count against convergence — and a freeze being added or
        // lifted resets the clock so the fleet always gets a full window once the gate reopens.
        // Without this, a release-gate freeze (a normal operator action) would time the loop out
        // and stop it entirely.
        let mut attempt = 0usize;
        let mut was_frozen = false;
        while attempt < 240 {
            let frozen = self.any_set_frozen().await;
            if frozen || frozen != was_frozen {
                attempt = 0;
            }
            was_frozen = frozen;
            // Convergence is a property of the cohort fleet; the external slice shares the
            // `/fleet` listing (total is 32 cohort + `DEMO_EXTERNAL_COUNT`) but is not part of
            // the throttled rollout, so scope both the target and the count to cohort members.
            let fleet = self.fleet().await?;
            let cohort: Vec<&FleetNode> =
                fleet.iter().filter(|node| is_cohort_member(node)).collect();
            let on_target = cohort
                .iter()
                .filter(|node| {
                    node.healthy
                        && node.in_load_balancer
                        && node.version.as_deref() == Some(converge_version.as_str())
                })
                .count();
            converged = cohort.len() == DEMO_NODE_COUNT && on_target == DEMO_NODE_COUNT;
            // Log progress each second so a slow or churning convergence is visible
            // (e.g. agents briefly reverting under the load of a fleet-wide upgrade).
            if !converged && attempt.is_multiple_of(2) {
                let gate = if frozen {
                    " (frozen — clock paused)"
                } else {
                    ""
                };
                self.event(format!(
                    "convergence: {on_target}/{DEMO_NODE_COUNT} agents on {converge_version}{gate}"
                ))
                .await;
            }
            if converged {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            attempt += 1;
        }
        if !converged {
            return Err(format!(
                "fleet did not converge onto {converge_version} within 240 seconds"
            )
            .into());
        }
        {
            let mut state = self.chaos.lock().await;
            state.updated_groups = (0..DEMO_COHORT_COUNT).map(cohort_group).collect();
            state.rolled_back_groups.clear();
            state.active_broken.clear();
            state.active_valid.clear();
            state.converging = false;
            state.completed_nodes = DEMO_COHORT_COUNT;
        }
        Ok(())
    }

    /// Publish one release major: a valid sample app, or an intentionally corrupt
    /// entrypoint that every agent's health check rejects. Content-addressed, so a
    /// republished major with unchanged bytes is a no-op for the fleet.
    fn build_release_source(
        &self,
        major: usize,
        broken: bool,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let data = PathBuf::from(
            env::var("DEMO_REPOSITORY_DATA").unwrap_or_else(|_| "/release-data".into()),
        );
        let version = format!("{major}.0.0");
        let bundle = data.join("demo-loop-fixtures").join(&version);
        std::fs::create_dir_all(bundle.join("bin"))?;
        std::fs::create_dir_all(bundle.join("config"))?;
        if broken {
            std::fs::write(
                bundle.join("bin/app"),
                b"intentionally corrupt entrypoint\n",
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    bundle.join("bin/app"),
                    std::fs::Permissions::from_mode(0o755),
                )?;
            }
        } else {
            std::fs::copy("/usr/local/bin/sampleapp", bundle.join("bin/app"))?;
        }
        std::fs::write(
            bundle.join("config/release.toml"),
            format!("version = \"{version}\"\n"),
        )?;
        Ok(bundle)
    }

    /// Publish `version` from `source` and roll `group` to it through the real **`updatectl
    /// deploy`** — the CI release tool: it builds the deterministic bundle, signs it, publishes
    /// it to the release repository (MinIO), and merge-patches the group's `application`. That
    /// is how releases execute in the demo now (no more `server publish-app` + hand-patch).
    ///
    /// `updatectl deploy` patches the application ref but not the deployment *identity*, so we
    /// bump it to `group@version` here — the throttle counts a member settled only once every
    /// one of its agents reports exactly that identity, healthy. Backend (bucket/endpoint/
    /// prefix/keys) + AWS creds come from the `UPDATECTL_*`/`AWS_*` env the demo pod carries.
    async fn deploy_group(
        &self,
        group: &str,
        version: &str,
        source: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = PathBuf::from(
            env::var("DEMO_REPOSITORY_DATA").unwrap_or_else(|_| "/release-data".into()),
        );
        let platform = std::fs::read_to_string(data.join("platform"))?
            .trim()
            .to_owned();
        let source = source.to_str().ok_or("non-UTF-8 source path")?;
        // Backend defaults match the demo's in-cluster MinIO; the signing keys live on the
        // shared release-repository PVC the bootstrap wrote them to. AWS creds come from the
        // pod env. Every value is overridable via `UPDATECTL_*` for a real CDN.
        let bucket = env::var("UPDATECTL_BUCKET").unwrap_or_else(|_| "updates".into());
        let prefix = env::var("UPDATECTL_PREFIX").unwrap_or_else(|_| "releases".into());
        let endpoint =
            env::var("UPDATECTL_ENDPOINT").unwrap_or_else(|_| "http://minio:9000".into());
        let region = env::var("UPDATECTL_REGION").unwrap_or_else(|_| "us-east-1".into());
        let keys_dir = env::var("UPDATECTL_KEYS_DIR")
            .unwrap_or_else(|_| data.join("release-keys").to_string_lossy().into_owned());
        let mut command = tokio::process::Command::new("/usr/local/bin/updatectl");
        command.args([
            "deploy",
            "--keys-dir",
            &keys_dir,
            "--bucket",
            &bucket,
            "--prefix",
            &prefix,
            "--endpoint",
            &endpoint,
            "--region",
            &region,
            "--namespace",
            &self.publisher.namespace,
            "--group",
            group,
            "--product",
            "app",
            "--channel",
            "stable",
            "--version",
            version,
            "--entrypoint",
            "bin/app",
            "--platform",
            &platform,
            "--source",
            source,
        ]);
        // Sign the provider set this release ships with into the app target, so an
        // ordered-fallback rollback to this version re-selects exactly these providers — app
        // and providers roll back as one signed unit.
        let provider_path = env::var("DEMO_PROVIDER_PATH").ok();
        let provider_sha = env::var("DEMO_PROVIDER_SHA256").ok();
        if let (Some(path), Some(sha)) = (&provider_path, &provider_sha) {
            command.args(["--provider-set-path", path, "--provider-set-sha256", sha]);
        }
        let status = command.status().await?;
        if !status.success() {
            return Err(format!("updatectl deploy failed for {group} {version}").into());
        }
        self.publisher
            .groups()
            .patch(
                group,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec":{"deployment":{
                    "name": format!("{group}@{version}")
                }}})),
            )
            .await?;
        Ok(())
    }

    /// Roll the single manual Magnolia node from v1 to v2 — the "Upgrade Magnolia" button.
    /// The operator observes the changed desired state, signs it, and the node runs the real
    /// custom, in-place upgrade (back the JCR up to another disk, reuse the repository, restore
    /// on failure). Idempotent: clicking again while it is already on v2 is a no-op.
    pub(crate) async fn upgrade_magnolia_manual(&self) -> Result<(), Box<dyn std::error::Error>> {
        let data = PathBuf::from(
            env::var("DEMO_REPOSITORY_DATA").unwrap_or_else(|_| "/release-data".into()),
        );
        let platform = std::fs::read_to_string(data.join("platform"))?
            .trim()
            .to_owned();
        let path = format!("products/magnolia/stable/2.0.0/{platform}/app");
        let sha256 = output(
            Command::new("/usr/local/bin/server").args([
                "target-sha256",
                "--repo",
                data.join("repository")
                    .to_str()
                    .ok_or("non-UTF-8 repo path")?,
                "--name",
                &path,
            ]),
        )?;
        self.publisher
            .groups()
            .patch(
                MAGNOLIA_MANUAL_GROUP,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec":{"deployment":{
                    "name": format!("{MAGNOLIA_MANUAL_GROUP}@2.0.0"),
                    "application":{"path":path,"sha256":sha256.trim()}
                }}})),
            )
            .await?;
        self.event(
            "manual Magnolia upgrade to v2 requested (custom in-place, backup + restore)".into(),
        )
        .await;
        Ok(())
    }

    /// Every `UpdateGroupSet`'s rollout calendar plus the operator's live gate verdict, for
    /// the UI's calendar panel. Cheap: one API list, no probes.
    pub(crate) async fn sets(&self) -> Result<Vec<SetCalendarView>, Box<dyn std::error::Error>> {
        let mut views = self
            .publisher
            .sets()
            .list(&Default::default())
            .await?
            .into_iter()
            .map(|set| {
                let name = set.name_any();
                let calendar = set
                    .spec
                    .calendar
                    .into_iter()
                    .map(|entry| CalendarEntryView {
                        date: entry.date,
                        start: entry.start,
                        end: entry.end,
                    })
                    .collect();
                let (frozen, member_count, rolling_count) = set
                    .status
                    .map(|status| (status.frozen, status.member_count, status.rolling_count))
                    .unwrap_or((None, None, None));
                SetCalendarView {
                    name,
                    calendar,
                    frozen,
                    member_count,
                    rolling_count,
                }
            })
            .collect::<Vec<_>>();
        views.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(views)
    }

    /// Whether the operator currently has any throttle set frozen (a set outside its rollout
    /// window/calendar). While frozen no new rollout is admitted, so the convergence wait must
    /// not count that time against its budget. Best-effort: an API hiccup reads as not-frozen so
    /// a transient error can never wedge the loop.
    async fn any_set_frozen(&self) -> bool {
        self.sets()
            .await
            .map(|views| views.iter().any(|view| view.frozen == Some(true)))
            .unwrap_or(false)
    }

    /// Append a whole-day (`00:00`–`24:00` UTC) rollout-calendar window for `date` to `set`,
    /// so the operator gates that set to the listed days. Idempotent per date. The date is
    /// validated with the operator's own [`updatec::CalendarEntry::validate`], so the UI can
    /// never write an entry the control plane would reject.
    pub(crate) async fn add_calendar_date(
        &self,
        set: &str,
        date: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entry = updatec::CalendarEntry {
            date: date.to_owned(),
            start: "00:00".to_owned(),
            end: "24:00".to_owned(),
        };
        entry.validate()?;
        let sets = self.publisher.sets();
        // A merge patch replaces the whole array, so read the current calendar, append, and
        // write it back — skipping a date the set already carries.
        let current = sets.get(set).await?;
        let mut calendar: Vec<serde_json::Value> = current
            .spec
            .calendar
            .iter()
            .map(|entry| serde_json::json!({"date": entry.date, "start": entry.start, "end": entry.end}))
            .collect();
        if !current.spec.calendar.iter().any(|entry| entry.date == date) {
            calendar.push(serde_json::json!({"date": date, "start": "00:00", "end": "24:00"}));
        }
        sets.patch(
            set,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"calendar": calendar}})),
        )
        .await?;
        self.event(format!(
            "rollout calendar: added {date} (00:00–24:00 UTC) to set {set}"
        ))
        .await;
        Ok(())
    }

    /// Drop every calendar entry from `set`, so it stops gating on dates (falls back to open,
    /// or to its recurring `rolloutWindows` if any). Lets the demo reset the panel.
    pub(crate) async fn clear_calendar(&self, set: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.publisher
            .sets()
            .patch(
                set,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({"spec": {"calendar": []}})),
            )
            .await?;
        self.event(format!("rollout calendar: cleared set {set}"))
            .await;
        Ok(())
    }

    pub(crate) async fn event(&self, event: String) {
        let mut state = self.chaos.lock().await;
        state.events.push(event);
        if state.events.len() > 100 {
            state.events.remove(0);
        }
    }

    /// The demo's one chaos mechanism, fired a random 0-5s into each rollout. It abruptly
    /// SIGKILLs pods — no graceful drain — so recovery is purely from persisted, PVC-backed
    /// state: a recreated agent must resume an interrupted cold-install from its install
    /// journal, recover a mid-flight upgrade from the update journal, relaunch the committed
    /// app, or restore Magnolia's in-place JCR from its backup disk.
    ///
    /// Two bounded targets, so it exercises recovery without ever breaching availability:
    ///   * Fleet pods — only pods already *draining* (out of the load balancer), and at most
    ///     [`DEMO_CHAOS_MAX_GROUPS_PER_SET`] cohort group per set, so the set's other group
    ///     keeps serving and no serving pod is ever removed.
    ///   * The controller — some rounds also crash the updatec operator, which reloads its
    ///     persisted admitted-deployment state and resumes the rollout where it left off.
    pub(crate) async fn inject_chaos(&self, seed: u64) {
        // Guarded at the one spawn site too; this covers any other caller.
        if self.chaos_disabled {
            return;
        }
        let mut rng = seed ^ 0x9E37_79B9_7F4A_7C15;
        let delay = Duration::from_millis(splitmix64(&mut rng) % 5_000);
        tokio::time::sleep(delay).await;

        // Folded-in control-plane chaos: crash the controller on ~half of rounds. Recovery is
        // from persisted state + lease expiry — a real crash test of the operator.
        if splitmix64(&mut rng).is_multiple_of(2) {
            self.crash_controller().await;
        }

        let Ok(fleet) = self.fleet().await else {
            return;
        };
        // Draining (out-of-pool) pods, grouped by set and then by cohort group, so we can cap
        // disruption to one group per set. Chaos never touches an in-pool (serving) pod.
        let mut draining: std::collections::HashMap<
            usize,
            std::collections::HashMap<usize, Vec<String>>,
        > = std::collections::HashMap::new();
        for node in &fleet {
            if node.in_load_balancer {
                continue;
            }
            if let (Some(set), Some(cohort)) =
                (node_set_index(&node.node), node_cohort_index(&node.node))
            {
                draining
                    .entry(set)
                    .or_default()
                    .entry(cohort)
                    .or_default()
                    .push(node.node.clone());
            }
        }
        let mut victims = Vec::new();
        for groups in draining.values() {
            // At most one cohort group per set: pick a single group and take all of its
            // already-draining pods, leaving every other group in the set untouched.
            let cohorts: Vec<usize> = groups.keys().copied().collect();
            for _ in 0..DEMO_CHAOS_MAX_GROUPS_PER_SET.min(cohorts.len()) {
                let cohort = cohorts[(splitmix64(&mut rng) as usize) % cohorts.len()];
                victims.extend(groups[&cohort].iter().cloned());
            }
        }
        if victims.is_empty() {
            self.event(format!(
                "seed {seed}: chaos found no draining pods to disrupt this round"
            ))
            .await;
            return;
        }
        for pod in &victims {
            self.event(format!(
                "seed {seed}: chaos SIGKILLs pod {pod} {:.1}s into the rollout; it recovers from its retained PVC",
                delay.as_secs_f64()
            ))
            .await;
            // Force-delete through the kube API — the equivalent of `kubectl delete --force
            // --grace-period=0`. The demo image ships no `kubectl`, so chaos (like the pod
            // labeler) must use the API directly, or every SIGKILL silently no-ops.
            if let Err(error) = self
                .publisher
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
                self.event(format!(
                    "seed {seed}: chaos could not delete pod {pod}: {error}"
                ))
                .await;
            }
        }
    }

    /// Abruptly crash the updatec controller (SIGKILL, no lease release), part of the one
    /// chaos mechanism. It reloads persisted state and resumes, so the rollout survives.
    async fn crash_controller(&self) {
        // Force-delete the controller pod(s) by label through the kube API (no `kubectl` in the
        // demo image). The operator reloads persisted state and resumes on the next pod.
        let killed = self
            .publisher
            .pods()
            .delete_collection(
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..Default::default()
                },
                &ListParams::default().labels("app=updatec-controller"),
            )
            .await;
        match killed {
            Ok(_) => {
                self.event(
                    "chaos: crashed the updatec controller; it reloads persisted state and resumes"
                        .into(),
                )
                .await;
            }
            Err(error) => {
                self.event(format!(
                    "chaos: could not delete the controller pod: {error}"
                ))
                .await;
            }
        }
    }

    pub(crate) fn page(&self) -> String {
        PAGE.to_owned()
    }
}
