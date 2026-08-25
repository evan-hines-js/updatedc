//! Resident, seeded release campaigns for the permanent chaos lab.
//!
//! One controller owns the complete campaign transaction: choose a release, state the expected
//! fleet result, apply the typed deployment, inject one bounded Chaos Mesh fault, wait for exact
//! convergence (or an expected rejection), recover, persist the result, and expose aggregate
//! metrics. A restart always re-applies the last known-good desired state before starting another
//! round, so there is no second ad-hoc recovery path.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::ByteString;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Api, Client, ResourceExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use updatec::{DeploymentSpec, UpdateAgent, UpdateGroup, UpdateGroupSet, UpdateRepository};

use crate::{agent_resource_name, fixture};

const STATE_SCHEMA: u8 = 1;
const BASELINE_VERSION: &str = "1.0.0";
const METRICS_PORT: u16 = 9091;
const METRICS_MAX_REQUEST: usize = 8 * 1024;
const SIGNING_KEY_FILES: [&str; 5] = [
    "root.pk8",
    "root.next.pk8",
    "targets.pk8",
    "snapshot.pk8",
    "timestamp.pk8",
];

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug)]
struct Config {
    namespace: String,
    seed: u64,
    agent_count: usize,
    round_interval: Duration,
    fault_duration: Duration,
    convergence_timeout: Duration,
    release_data: PathBuf,
    state_dir: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self> {
        let config = Self {
            namespace: env::var("UPDATEC_SOAK_NAMESPACE")
                .unwrap_or_else(|_| fixture::NAMESPACE.into()),
            seed: env_u64("UPDATEC_SOAK_SEED", 2_026_082_500, 1, i64::MAX as u64)?,
            agent_count: env_u64("UPDATEC_SOAK_AGENT_COUNT", 6, 3, 60)? as usize,
            round_interval: Duration::from_secs(env_u64(
                "UPDATEC_SOAK_ROUND_INTERVAL_SECONDS",
                90,
                10,
                3600,
            )?),
            fault_duration: Duration::from_secs(env_u64("UPDATEC_SOAK_FAULT_SECONDS", 20, 5, 120)?),
            convergence_timeout: Duration::from_secs(env_u64(
                "UPDATEC_SOAK_CONVERGENCE_SECONDS",
                300,
                60,
                1800,
            )?),
            release_data: env::var_os("UPDATEC_SOAK_RELEASE_DATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/release-data")),
            state_dir: env::var_os("UPDATEC_SOAK_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/state")),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if !self.agent_count.is_multiple_of(fixture::SOAK_GROUPS.len()) {
            return Err(format!(
                "agent count {} must divide evenly across {} soak groups",
                self.agent_count,
                fixture::SOAK_GROUPS.len()
            )
            .into());
        }
        if self.fault_duration >= self.convergence_timeout {
            return Err("fault duration must be shorter than the convergence budget".into());
        }
        if self.namespace != fixture::NAMESPACE {
            return Err(format!(
                "soak namespace {:?} disagrees with the shared fixture namespace {:?}",
                self.namespace,
                fixture::NAMESPACE
            )
            .into());
        }
        Ok(())
    }

    fn state_path(&self) -> PathBuf {
        self.state_dir.join("campaign.json")
    }

    fn journal_path(&self) -> PathBuf {
        self.state_dir.join("campaigns.jsonl")
    }
}

fn env_u64(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|error| format!("{name} must be an integer: {error}"))?,
        Err(env::VarError::NotPresent) => default,
        Err(error) => return Err(format!("cannot read {name}: {error}").into()),
    };
    if !(min..=max).contains(&value) {
        return Err(format!("{name} must be in {min}..={max}, got {value}").into());
    }
    Ok(value)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignState {
    schema: u8,
    seed: u64,
    round: u64,
    desired: BTreeMap<String, String>,
    campaigns: u64,
    successful_campaigns: u64,
    failed_campaigns: u64,
    release_assignments: u64,
    expected_rejections: u64,
    recoveries: u64,
    consecutive_failures: u64,
    last_success_timestamp: i64,
    last_failure_timestamp: i64,
}

impl CampaignState {
    fn fresh(seed: u64) -> Self {
        Self {
            schema: STATE_SCHEMA,
            seed,
            round: 0,
            desired: fixture::SOAK_GROUPS
                .into_iter()
                .map(|name| (name.into(), BASELINE_VERSION.into()))
                .collect(),
            campaigns: 0,
            successful_campaigns: 0,
            failed_campaigns: 0,
            release_assignments: 0,
            expected_rejections: 0,
            recoveries: 0,
            consecutive_failures: 0,
            last_success_timestamp: 0,
            last_failure_timestamp: 0,
        }
    }

    fn load(config: &Config) -> Result<Self> {
        fs::create_dir_all(&config.state_dir)?;
        let path = config.state_path();
        let state = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Self::fresh(config.seed)
        };
        state.validate(config)?;
        Ok(state)
    }

    fn validate(&self, config: &Config) -> Result<()> {
        if self.schema != STATE_SCHEMA {
            return Err(format!("unsupported soak state schema {}", self.schema).into());
        }
        if self.seed != config.seed {
            return Err(format!(
                "persisted soak seed {} differs from configured seed {}; reset the soak PVC to start a different campaign",
                self.seed, config.seed
            )
            .into());
        }
        let keys: Vec<&str> = self.desired.keys().map(String::as_str).collect();
        if keys != fixture::SOAK_GROUPS.to_vec() {
            return Err(format!("persisted desired groups are not canonical: {keys:?}").into());
        }
        Ok(())
    }

    fn persist(&self, config: &Config) -> Result<()> {
        let path = config.state_path();
        let temporary = config.state_dir.join("campaign.json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FaultKind {
    NetworkPartition,
    IoError,
    AgentKill,
    ControllerKill,
}

impl FaultKind {
    const ALL: [Self; 4] = [
        Self::NetworkPartition,
        Self::IoError,
        Self::AgentKill,
        Self::ControllerKill,
    ];

    const fn index(self) -> usize {
        match self {
            Self::NetworkPartition => 0,
            Self::IoError => 1,
            Self::AgentKill => 2,
            Self::ControllerKill => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::NetworkPartition => "network_partition",
            Self::IoError => "io_error",
            Self::AgentKill => "agent_kill",
            Self::ControllerKill => "controller_kill",
        }
    }

    const fn resource(self) -> (&'static str, &'static str) {
        match self {
            Self::NetworkPartition => ("NetworkChaos", "networkchaos"),
            Self::IoError => ("IOChaos", "iochaos"),
            Self::AgentKill | Self::ControllerKill => ("PodChaos", "podchaos"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct RoundPlan {
    round: u64,
    seed: u64,
    groups: Vec<String>,
    fault: FaultKind,
    target_ordinal: usize,
    expected_rejection: bool,
}

fn plan_round(state: &CampaignState, agent_count: usize) -> RoundPlan {
    let round = state.round + 1;
    let mut rng = state.seed ^ round.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let fault = FaultKind::ALL[(splitmix64(&mut rng) as usize) % FaultKind::ALL.len()];
    let target_ordinal = (splitmix64(&mut rng) as usize) % agent_count;
    let expected_rejection = round.is_multiple_of(10);
    let group_count = if expected_rejection {
        1
    } else {
        1 + (splitmix64(&mut rng) as usize) % fixture::SOAK_GROUPS.len()
    };
    let mut groups = fixture::SOAK_GROUPS.map(str::to_owned);
    for index in (1..groups.len()).rev() {
        let selected = (splitmix64(&mut rng) as usize) % (index + 1);
        groups.swap(index, selected);
    }
    RoundPlan {
        round,
        seed: rng,
        groups: groups.into_iter().take(group_count).collect(),
        fault,
        target_ordinal,
        expected_rejection,
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[derive(Clone, Debug)]
struct Metrics {
    started_timestamp: i64,
    bootstrap_ready: bool,
    campaign_healthy: bool,
    round: u64,
    round_seed: u64,
    campaigns: u64,
    successful_campaigns: u64,
    failed_campaigns: u64,
    release_assignments: u64,
    expected_rejections: u64,
    recoveries: u64,
    consecutive_failures: u64,
    last_success_timestamp: i64,
    last_failure_timestamp: i64,
    last_convergence_seconds: f64,
    fleet_expected_nodes: usize,
    fleet_converged_nodes: usize,
    active_fault: Option<FaultKind>,
    faults: [u64; 4],
    fault_failures: [u64; 4],
}

impl Metrics {
    fn from_state(state: &CampaignState, expected_nodes: usize) -> Self {
        Self {
            started_timestamp: Utc::now().timestamp(),
            bootstrap_ready: false,
            campaign_healthy: false,
            round: state.round,
            round_seed: 0,
            campaigns: state.campaigns,
            successful_campaigns: state.successful_campaigns,
            failed_campaigns: state.failed_campaigns,
            release_assignments: state.release_assignments,
            expected_rejections: state.expected_rejections,
            recoveries: state.recoveries,
            consecutive_failures: state.consecutive_failures,
            last_success_timestamp: state.last_success_timestamp,
            last_failure_timestamp: state.last_failure_timestamp,
            last_convergence_seconds: 0.0,
            fleet_expected_nodes: expected_nodes,
            fleet_converged_nodes: 0,
            active_fault: None,
            faults: [0; 4],
            fault_failures: [0; 4],
        }
    }

    fn sync_state(&mut self, state: &CampaignState) {
        self.round = state.round;
        self.campaigns = state.campaigns;
        self.successful_campaigns = state.successful_campaigns;
        self.failed_campaigns = state.failed_campaigns;
        self.release_assignments = state.release_assignments;
        self.expected_rejections = state.expected_rejections;
        self.recoveries = state.recoveries;
        self.consecutive_failures = state.consecutive_failures;
        self.last_success_timestamp = state.last_success_timestamp;
        self.last_failure_timestamp = state.last_failure_timestamp;
    }

    fn render(&self) -> String {
        let mut output = String::new();
        metric(
            &mut output,
            "updatec_soak_started_timestamp_seconds",
            self.started_timestamp,
        );
        metric(
            &mut output,
            "updatec_soak_bootstrap_ready",
            u8::from(self.bootstrap_ready),
        );
        metric(
            &mut output,
            "updatec_soak_campaign_healthy",
            u8::from(self.campaign_healthy),
        );
        metric(&mut output, "updatec_soak_round", self.round);
        metric(&mut output, "updatec_soak_round_seed", self.round_seed);
        metric(&mut output, "updatec_soak_campaigns_total", self.campaigns);
        metric(
            &mut output,
            "updatec_soak_successful_campaigns_total",
            self.successful_campaigns,
        );
        metric(
            &mut output,
            "updatec_soak_failed_campaigns_total",
            self.failed_campaigns,
        );
        metric(
            &mut output,
            "updatec_soak_release_assignments_total",
            self.release_assignments,
        );
        metric(
            &mut output,
            "updatec_soak_expected_rejections_total",
            self.expected_rejections,
        );
        metric(
            &mut output,
            "updatec_soak_recoveries_total",
            self.recoveries,
        );
        metric(
            &mut output,
            "updatec_soak_consecutive_failures",
            self.consecutive_failures,
        );
        metric(
            &mut output,
            "updatec_soak_last_success_timestamp_seconds",
            self.last_success_timestamp,
        );
        metric(
            &mut output,
            "updatec_soak_last_failure_timestamp_seconds",
            self.last_failure_timestamp,
        );
        metric(
            &mut output,
            "updatec_soak_last_convergence_seconds",
            self.last_convergence_seconds,
        );
        metric(
            &mut output,
            "updatec_soak_fleet_expected_nodes",
            self.fleet_expected_nodes,
        );
        metric(
            &mut output,
            "updatec_soak_fleet_converged_nodes",
            self.fleet_converged_nodes,
        );
        for kind in FaultKind::ALL {
            let active = self.active_fault == Some(kind);
            output.push_str(&format!(
                "updatec_soak_fault_active{{kind=\"{}\"}} {}\n",
                kind.name(),
                u8::from(active)
            ));
            output.push_str(&format!(
                "updatec_soak_faults_total{{kind=\"{}\"}} {}\n",
                kind.name(),
                self.faults[kind.index()]
            ));
            output.push_str(&format!(
                "updatec_soak_fault_failures_total{{kind=\"{}\"}} {}\n",
                kind.name(),
                self.fault_failures[kind.index()]
            ));
        }
        output
    }
}

fn metric(output: &mut String, name: &str, value: impl std::fmt::Display) {
    output.push_str(&format!("{name} {value}\n"));
}

#[derive(Clone)]
struct ReleaseCatalog {
    platform: String,
    root_json: String,
    provider_sha: String,
    valid_versions: Vec<String>,
    release_data: PathBuf,
}

impl ReleaseCatalog {
    async fn load(config: &Config) -> Result<Self> {
        let ready = config.release_data.join("ready");
        if !ready.is_file() {
            return Err(format!("release repository is not ready at {}", ready.display()).into());
        }
        let platform = fs::read_to_string(config.release_data.join("platform"))?
            .trim()
            .to_owned();
        let root_json =
            fs::read_to_string(config.release_data.join("repository/metadata/root.json"))?;
        let valid_versions = fs::read_to_string(config.release_data.join("valid-versions"))?
            .lines()
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if valid_versions.len() < 3 || !valid_versions.iter().any(|v| v == BASELINE_VERSION) {
            return Err("release catalog has no usable baseline corpus".into());
        }
        let mut catalog = Self {
            platform,
            root_json,
            provider_sha: String::new(),
            valid_versions,
            release_data: config.release_data.clone(),
        };
        catalog.provider_sha = catalog.target_sha("provider-sets/default.json").await?;
        Ok(catalog)
    }

    async fn app_sha(&self, version: &str) -> Result<String> {
        self.target_sha(&format!(
            "products/app/stable/{version}/{}/app",
            self.platform
        ))
        .await
    }

    async fn target_sha(&self, target: &str) -> Result<String> {
        server_output(&[
            "target-sha256".into(),
            "--repo".into(),
            self.release_data.join("repository").display().to_string(),
            "--name".into(),
            target.into(),
        ])
        .await
    }

    fn deployment(&self, group: &str, version: &str, sha: &str) -> DeploymentSpec {
        fixture::deployment(
            group,
            version,
            &self.platform,
            sha,
            &self.provider_sha,
            &self.root_json,
        )
    }

    fn next_valid(&self, state: &CampaignState, plan: &RoundPlan, group: &str) -> &str {
        let mut cursor = (plan.seed as usize ^ group.len()) % self.valid_versions.len();
        for _ in 0..self.valid_versions.len() {
            let candidate = &self.valid_versions[cursor];
            if state.desired.get(group) != Some(candidate) {
                return candidate;
            }
            cursor = (cursor + 1) % self.valid_versions.len();
        }
        unreachable!("the validated release corpus has more than one version")
    }

    async fn ensure_corrupt(&self, round: u64) -> Result<(String, String)> {
        let version = format!("1000000.{round}.0");
        let target = format!("products/app/stable/{version}/{}/app", self.platform);
        if let Ok(sha) = self.target_sha(&target).await {
            return Ok((version, sha));
        }
        let source = self.release_data.join("soak-fixtures").join(&version);
        fs::create_dir_all(source.join("bin"))?;
        fs::create_dir_all(source.join("config"))?;
        let app = source.join("bin/app");
        fs::write(
            &app,
            format!("intentionally corrupt soak release {version}\n"),
        )?;
        fs::set_permissions(&app, fs::Permissions::from_mode(0o755))?;
        fs::write(
            source.join("config/release.toml"),
            format!("version = \"{version}\"\n"),
        )?;
        server_output(&[
            "publish-app".into(),
            "--repo".into(),
            self.release_data.join("repository").display().to_string(),
            "--keys".into(),
            self.release_data.join("keys").display().to_string(),
            "--product".into(),
            "app".into(),
            "--channel".into(),
            "stable".into(),
            "--version".into(),
            version.clone(),
            "--entrypoint".into(),
            "bin/app".into(),
            "--bundle".into(),
            format!("{}={}", self.platform, source.display()),
        ])
        .await?;
        Ok((version, self.target_sha(&target).await?))
    }
}

async fn server_output(args: &[String]) -> Result<String> {
    let output = Command::new("/usr/local/bin/server")
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "server {} failed: {}",
            args.first().map_or("command", String::as_str),
            stderr.chars().take(4096).collect::<String>()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct Campaign {
    client: Client,
    config: Config,
    catalog: ReleaseCatalog,
    metrics: Arc<RwLock<Metrics>>,
}

impl Campaign {
    async fn bootstrap(
        client: Client,
        config: Config,
        metrics: Arc<RwLock<Metrics>>,
    ) -> Result<Self> {
        let catalog = ReleaseCatalog::load(&config).await?;
        ensure_signing_secret(&client, &config).await?;
        ensure_control_resources(&client, &config, &catalog).await?;
        metrics
            .write()
            .expect("metrics lock poisoned")
            .bootstrap_ready = true;
        Ok(Self {
            client,
            config,
            catalog,
            metrics,
        })
    }

    async fn wait_for_fleet(&self) -> Result<()> {
        let agents: Api<UpdateAgent> = Api::namespaced(self.client.clone(), &self.config.namespace);
        loop {
            let mut complete = true;
            for ordinal in 0..self.config.agent_count {
                let resource = agent_resource_name(ordinal);
                let Some(agent) = agents.get_opt(&resource).await? else {
                    complete = false;
                    continue;
                };
                if agent.spec.identity.kind != updatec::AgentIdentityKind::Enrolled {
                    complete = false;
                    continue;
                }
                let group = fixture::SOAK_GROUPS[ordinal % fixture::SOAK_GROUPS.len()];
                let expected = BTreeMap::from([
                    (fixture::SOAK_COHORT_LABEL.to_owned(), group.to_owned()),
                    (fixture::SOAK_NODE_LABEL.to_owned(), agent_hostname(ordinal)),
                ]);
                let current: BTreeMap<&str, &str> = agent
                    .spec
                    .labels
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect();
                let expected_refs: BTreeMap<&str, &str> = expected
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str()))
                    .collect();
                if current != expected_refs {
                    let mut replacement = agent;
                    replacement.spec.labels = expected;
                    agents
                        .replace(&resource, &PostParams::default(), &replacement)
                        .await?;
                    complete = false;
                }
            }
            if complete {
                println!(
                    "[soak] all {} agents are enrolled and assigned across {:?}",
                    self.config.agent_count,
                    fixture::SOAK_GROUPS
                );
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    async fn restore_known_good(&self, state: &CampaignState) -> Result<()> {
        for (group, version) in &state.desired {
            let sha = self.catalog.app_sha(version).await?;
            self.patch_group(group, self.catalog.deployment(group, version, &sha))
                .await?;
        }
        self.cleanup_faults().await;
        self.wait_converged(&state.desired).await?;
        Ok(())
    }

    async fn run_round(&self, state: &mut CampaignState, plan: &RoundPlan) -> Result<()> {
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .round_seed = plan.seed;
        println!(
            "[soak] round {} seed {} groups {:?} fault {} expected_rejection={}",
            plan.round,
            plan.seed,
            plan.groups,
            plan.fault.name(),
            plan.expected_rejection
        );
        if plan.expected_rejection {
            self.run_rejection_round(state, plan).await
        } else {
            self.run_valid_round(state, plan).await
        }
    }

    async fn run_valid_round(&self, state: &mut CampaignState, plan: &RoundPlan) -> Result<()> {
        let mut desired = state.desired.clone();
        for group in &plan.groups {
            let version = self.catalog.next_valid(state, plan, group).to_owned();
            let sha = self.catalog.app_sha(&version).await?;
            self.patch_group(group, self.catalog.deployment(group, &version, &sha))
                .await?;
            desired.insert(group.clone(), version);
            state.release_assignments += 1;
        }
        let convergence = self.wait_converged(&desired);
        let fault = self.inject_fault(plan);
        let (duration, ()) = tokio::try_join!(convergence, fault)?;
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .last_convergence_seconds = duration.as_secs_f64();
        state.desired = desired;
        Ok(())
    }

    async fn run_rejection_round(&self, state: &mut CampaignState, plan: &RoundPlan) -> Result<()> {
        let group = plan
            .groups
            .first()
            .expect("a rejection round has one group");
        let (bad_version, bad_sha) = self.catalog.ensure_corrupt(plan.round).await?;
        self.patch_group(
            group,
            self.catalog.deployment(group, &bad_version, &bad_sha),
        )
        .await?;
        state.release_assignments += 1;
        let rejected = self.wait_rejected(group, &state.desired);
        let fault = self.inject_fault(plan);
        tokio::try_join!(rejected, fault)?;
        state.expected_rejections += 1;

        let recovery_version = self.catalog.next_valid(state, plan, group).to_owned();
        let recovery_sha = self.catalog.app_sha(&recovery_version).await?;
        self.patch_group(
            group,
            self.catalog
                .deployment(group, &recovery_version, &recovery_sha),
        )
        .await?;
        state.release_assignments += 1;
        let mut desired = state.desired.clone();
        desired.insert(group.clone(), recovery_version);
        let duration = self.wait_converged(&desired).await?;
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .last_convergence_seconds = duration.as_secs_f64();
        state.desired = desired;
        Ok(())
    }

    async fn patch_group(&self, name: &str, deployment: DeploymentSpec) -> Result<()> {
        let groups: Api<UpdateGroup> = Api::namespaced(self.client.clone(), &self.config.namespace);
        groups
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"spec": {"deployment": deployment}})),
            )
            .await?;
        Ok(())
    }

    async fn wait_converged(&self, desired: &BTreeMap<String, String>) -> Result<Duration> {
        let started = Instant::now();
        let agents: Api<UpdateAgent> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let mut last = Vec::new();
        while started.elapsed() < self.config.convergence_timeout {
            let mut converged = 0usize;
            last.clear();
            for ordinal in 0..self.config.agent_count {
                let resource = agent_resource_name(ordinal);
                let group = fixture::SOAK_GROUPS[ordinal % fixture::SOAK_GROUPS.len()];
                let expected = desired
                    .get(group)
                    .ok_or_else(|| format!("no desired version for {group}"))?;
                match agents.get_opt(&resource).await? {
                    Some(agent) => {
                        let status = agent.status.as_ref();
                        let exact = status.is_some_and(|status| {
                            status.selected_group.as_deref() == Some(group)
                                && status.reported_version.as_deref() == Some(expected)
                                && status.reported_ready == Some(true)
                        });
                        if exact {
                            converged += 1;
                        } else {
                            last.push(format!(
                                "{}={}/{}/{}",
                                agent_hostname(ordinal),
                                status
                                    .and_then(|status| status.selected_group.as_deref())
                                    .unwrap_or("unassigned"),
                                status
                                    .and_then(|status| status.reported_version.as_deref())
                                    .unwrap_or("unknown"),
                                status
                                    .and_then(|status| status.reported_ready)
                                    .unwrap_or(false)
                            ));
                        }
                    }
                    None => last.push(format!("{}=missing", agent_hostname(ordinal))),
                }
            }
            self.metrics
                .write()
                .expect("metrics lock poisoned")
                .fleet_converged_nodes = converged;
            if converged == self.config.agent_count {
                return Ok(started.elapsed());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(format!(
            "fleet did not converge within {}s; lagging [{}]",
            self.config.convergence_timeout.as_secs(),
            last.join(", ")
        )
        .into())
    }

    async fn wait_rejected(&self, group: &str, stable: &BTreeMap<String, String>) -> Result<()> {
        let groups: Api<UpdateGroup> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let started = Instant::now();
        while started.elapsed() < self.config.convergence_timeout {
            let resource = groups.get(group).await?;
            let rejected = resource.status.as_ref().is_some_and(|status| {
                status.conditions.iter().any(|condition| {
                    condition.condition_type == "Ready"
                        && condition.status == "False"
                        && condition.reason == "Rejected"
                })
            });
            if rejected && self.group_is_stable(group, stable).await? {
                println!(
                    "[soak] {group} rejected the corrupt release and recovered its predecessor"
                );
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(format!(
            "{group} did not reach the expected rejected-and-recovered state within {}s",
            self.config.convergence_timeout.as_secs()
        )
        .into())
    }

    async fn group_is_stable(
        &self,
        group: &str,
        stable: &BTreeMap<String, String>,
    ) -> Result<bool> {
        let expected = stable
            .get(group)
            .ok_or_else(|| format!("no stable version for {group}"))?;
        let agents: Api<UpdateAgent> = Api::namespaced(self.client.clone(), &self.config.namespace);
        for ordinal in 0..self.config.agent_count {
            if fixture::SOAK_GROUPS[ordinal % fixture::SOAK_GROUPS.len()] != group {
                continue;
            }
            let Some(agent) = agents.get_opt(&agent_resource_name(ordinal)).await? else {
                return Ok(false);
            };
            let Some(status) = agent.status else {
                return Ok(false);
            };
            if status.reported_version.as_deref() != Some(expected)
                || status.reported_ready != Some(true)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn inject_fault(&self, plan: &RoundPlan) -> Result<()> {
        let name = format!("soak-round-{}", plan.round);
        let (api, object) = self.fault_object(plan, &name).await?;
        {
            let mut metrics = self.metrics.write().expect("metrics lock poisoned");
            metrics.active_fault = Some(plan.fault);
        }
        let result = async {
            api.create(&PostParams::default(), &object).await?;
            wait_chaos_injected(&api, &name).await?;
            {
                let mut metrics = self.metrics.write().expect("metrics lock poisoned");
                metrics.faults[plan.fault.index()] += 1;
            }
            println!("[soak] {} injected by Chaos Mesh", plan.fault.name());
            tokio::time::sleep(self.config.fault_duration).await;
            delete_dynamic(&api, &name).await?;
            println!("[soak] {} recovered", plan.fault.name());
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .active_fault = None;
        if result.is_err() {
            self.metrics
                .write()
                .expect("metrics lock poisoned")
                .fault_failures[plan.fault.index()] += 1;
            let _ = delete_dynamic(&api, &name).await;
        }
        result
    }

    async fn fault_object(
        &self,
        plan: &RoundPlan,
        name: &str,
    ) -> Result<(Api<DynamicObject>, DynamicObject)> {
        let (kind, plural) = plan.fault.resource();
        let api = dynamic_api(self.client.clone(), &self.config.namespace, kind, plural);
        let target = match plan.fault {
            FaultKind::ControllerKill => self.controller_pod().await?,
            _ => agent_hostname(plan.target_ordinal),
        };
        let selector = json!({
            "namespaces": [self.config.namespace],
            "pods": {(self.config.namespace.clone()): [target]},
        });
        let spec = match plan.fault {
            FaultKind::NetworkPartition => json!({
                "action": "partition",
                "mode": "all",
                "selector": selector,
                "direction": "both",
                "target": {
                    "mode": "all",
                    "selector": {
                        "namespaces": [self.config.namespace],
                        "labelSelectors": {"updated.dev/chaos-target": "true"},
                    },
                },
            }),
            FaultKind::IoError => json!({
                "action": "fault",
                "mode": "all",
                "selector": selector,
                "volumePath": "/var/lib/updated",
                "path": "/var/lib/updated/*",
                "errno": 5,
                "percent": 25,
                "containerNames": ["agent"],
            }),
            FaultKind::AgentKill | FaultKind::ControllerKill => json!({
                "action": "pod-kill",
                "mode": "all",
                "selector": selector,
            }),
        };
        let object = serde_json::from_value(json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": kind,
            "metadata": {"name": name, "namespace": self.config.namespace},
            "spec": spec,
        }))?;
        Ok((api, object))
    }

    async fn controller_pod(&self) -> Result<String> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.config.namespace);
        let selected = pods
            .list(&ListParams::default().labels("app=updatec-controller"))
            .await?;
        let names = selected
            .items
            .into_iter()
            .map(|pod| pod.name_any())
            .collect::<Vec<_>>();
        match names.as_slice() {
            [name] => Ok(name.clone()),
            _ => Err(format!("expected one updatec controller pod, found {names:?}").into()),
        }
    }

    async fn cleanup_faults(&self) {
        // PodChaos backs both kill variants, so visit each Kubernetes resource type once.
        for kind in [
            FaultKind::NetworkPartition,
            FaultKind::IoError,
            FaultKind::AgentKill,
        ] {
            let (resource_kind, plural) = kind.resource();
            let api = dynamic_api(
                self.client.clone(),
                &self.config.namespace,
                resource_kind,
                plural,
            );
            if let Ok(objects) = api.list(&ListParams::default()).await {
                for object in objects {
                    if object.name_any().starts_with("soak-round-") {
                        let _ = delete_dynamic(&api, &object.name_any()).await;
                    }
                }
            }
        }
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .active_fault = None;
    }
}

fn agent_hostname(ordinal: usize) -> String {
    format!("agent-{ordinal}")
}

fn dynamic_api(client: Client, namespace: &str, kind: &str, plural: &str) -> Api<DynamicObject> {
    let mut resource =
        ApiResource::from_gvk(&GroupVersionKind::gvk("chaos-mesh.org", "v1alpha1", kind));
    resource.plural = plural.into();
    Api::namespaced_with(client, namespace, &resource)
}

async fn wait_chaos_injected(api: &Api<DynamicObject>, name: &str) -> Result<()> {
    for _ in 0..30 {
        if let Some(object) = api.get_opt(name).await? {
            let injected =
                object.data["status"]["conditions"]
                    .as_array()
                    .is_some_and(|conditions| {
                        conditions.iter().any(|condition| {
                            condition["type"] == "AllInjected" && condition["status"] == "True"
                        })
                    });
            if injected {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("Chaos Mesh did not report {name} injected within 30s").into())
}

async fn delete_dynamic(api: &Api<DynamicObject>, name: &str) -> Result<()> {
    if api.get_opt(name).await?.is_none() {
        return Ok(());
    }
    api.delete(name, &DeleteParams::default()).await?;
    for _ in 0..60 {
        if api.get_opt(name).await?.is_none() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("Chaos Mesh did not recover and delete {name} within 60s").into())
}

async fn ensure_signing_secret(client: &Client, config: &Config) -> Result<()> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &config.namespace);
    if let Some(secret) = secrets.get_opt(fixture::SIGNING_SECRET).await? {
        validate_signing_secret(&secret)?;
        return Ok(());
    }
    let seed = config.state_dir.join("control-signing");
    let ready = seed.join("ready");
    if !ready.is_file() {
        let repository = seed.join("repository");
        let keys = seed.join("keys");
        if seed.exists() {
            fs::remove_dir_all(&seed)?;
        }
        fs::create_dir_all(&seed)?;
        server_output(&[
            "init".into(),
            "--repo".into(),
            repository.display().to_string(),
            "--keys".into(),
            keys.display().to_string(),
        ])
        .await?;
        fs::write(&ready, b"ready")?;
    }
    let keys = seed.join("keys");
    let mut data = BTreeMap::new();
    for name in SIGNING_KEY_FILES {
        data.insert(name.into(), ByteString(fs::read(keys.join(name))?));
    }
    let secret = Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(fixture::SIGNING_SECRET.into()),
            namespace: Some(config.namespace.clone()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/part-of".into(),
                "updatedc-chaos-lab".into(),
            )])),
            ..Default::default()
        },
        data: Some(data),
        type_: Some("Opaque".into()),
        ..Default::default()
    };
    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 409 => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_signing_secret(secret: &Secret) -> Result<()> {
    if secret.type_.as_deref() != Some("Opaque") {
        return Err("the TUF signing Secret must have type Opaque".into());
    }
    let data = secret
        .data
        .as_ref()
        .ok_or("the TUF signing Secret has no binary data")?;
    let actual = data.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = SIGNING_KEY_FILES.into_iter().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("the TUF signing Secret has non-canonical keys: {actual:?}").into());
    }
    if data.values().any(|value| value.0.is_empty()) {
        return Err("the TUF signing Secret contains an empty private key".into());
    }
    Ok(())
}

async fn ensure_control_resources(
    client: &Client,
    config: &Config,
    catalog: &ReleaseCatalog,
) -> Result<()> {
    let sha = catalog.app_sha(BASELINE_VERSION).await?;
    let repository_deployment = catalog.deployment("default", BASELINE_VERSION, &sha);
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), &config.namespace);
    let apply = PatchParams::apply("updatec-soak").force();
    repositories
        .patch(
            fixture::REPOSITORY_NAME,
            &apply,
            &Patch::Apply(&fixture::repository(repository_deployment)),
        )
        .await?;
    let groups: Api<UpdateGroup> = Api::namespaced(client.clone(), &config.namespace);
    for name in fixture::SOAK_GROUPS {
        groups
            .patch(
                name,
                &apply,
                &Patch::Apply(&fixture::group(
                    name,
                    catalog.deployment(name, BASELINE_VERSION, &sha),
                )),
            )
            .await?;
    }
    let sets: Api<UpdateGroupSet> = Api::namespaced(client.clone(), &config.namespace);
    sets.patch(
        fixture::SOAK_GROUP_SET,
        &apply,
        &Patch::Apply(&fixture::group_set()),
    )
    .await?;
    Ok(())
}

#[derive(Serialize)]
struct CampaignRecord<'a> {
    schema: u8,
    timestamp: String,
    outcome: &'a str,
    duration_seconds: f64,
    plan: &'a RoundPlan,
    error: Option<&'a str>,
}

fn append_record(
    config: &Config,
    plan: &RoundPlan,
    outcome: &str,
    duration: Duration,
    error: Option<&str>,
) -> Result<()> {
    let error = error.map(|message| {
        let boundary = message
            .char_indices()
            .nth(2048)
            .map_or(message.len(), |(index, _)| index);
        &message[..boundary]
    });
    let record = CampaignRecord {
        schema: STATE_SCHEMA,
        timestamp: Utc::now().to_rfc3339(),
        outcome,
        duration_seconds: duration.as_secs_f64(),
        plan,
        error,
    };
    let mut line = serde_json::to_vec(&record)?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(config.journal_path())?;
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(())
}

pub(crate) async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let mut state = CampaignState::load(&config)?;
    state.persist(&config)?;
    let metrics = Arc::new(RwLock::new(Metrics::from_state(&state, config.agent_count)));
    tokio::spawn(serve_metrics(metrics.clone()));
    let client = Client::try_default().await?;

    let campaign = loop {
        match Campaign::bootstrap(client.clone(), config.clone(), metrics.clone()).await {
            Ok(campaign) => break campaign,
            Err(error) => {
                println!("[soak] bootstrap not ready: {error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    println!("[soak] release and control resources are bootstrapped");
    campaign.wait_for_fleet().await?;
    campaign.restore_known_good(&state).await?;
    metrics
        .write()
        .expect("metrics lock poisoned")
        .campaign_healthy = true;

    loop {
        let plan = plan_round(&state, config.agent_count);
        let started = Instant::now();
        state.campaigns += 1;
        let result = campaign.run_round(&mut state, &plan).await;
        state.round = plan.round;
        match result {
            Ok(()) => {
                state.successful_campaigns += 1;
                state.consecutive_failures = 0;
                state.last_success_timestamp = Utc::now().timestamp();
                append_record(&config, &plan, "succeeded", started.elapsed(), None)?;
                println!("[soak] round {} succeeded", plan.round);
                metrics
                    .write()
                    .expect("metrics lock poisoned")
                    .campaign_healthy = true;
            }
            Err(error) => {
                let message = error.to_string();
                state.failed_campaigns += 1;
                state.consecutive_failures += 1;
                state.last_failure_timestamp = Utc::now().timestamp();
                append_record(&config, &plan, "failed", started.elapsed(), Some(&message))?;
                println!("[soak] round {} failed: {message}", plan.round);
                metrics
                    .write()
                    .expect("metrics lock poisoned")
                    .campaign_healthy = false;
                if campaign.restore_known_good(&state).await.is_ok() {
                    state.recoveries += 1;
                    println!("[soak] restored the last known-good fleet state after failure");
                }
            }
        }
        state.persist(&config)?;
        metrics
            .write()
            .expect("metrics lock poisoned")
            .sync_state(&state);
        tokio::time::sleep(config.round_interval).await;
    }
}

async fn serve_metrics(metrics: Arc<RwLock<Metrics>>) {
    let listener = loop {
        match TcpListener::bind(("0.0.0.0", METRICS_PORT)).await {
            Ok(listener) => break listener,
            Err(error) => {
                println!("[soak] metrics bind failed: {error}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_metrics_connection(stream, metrics).await {
                        println!("[soak] metrics request failed: {error}");
                    }
                });
            }
            Err(error) => {
                println!("[soak] metrics accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_metrics_connection(
    mut stream: TcpStream,
    metrics: Arc<RwLock<Metrics>>,
) -> Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if read == 0 {
            return Err("metrics peer closed before completing headers".into());
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > METRICS_MAX_REQUEST {
            return Err("metrics request headers exceed the bound".into());
        }
    }
    let first = std::str::from_utf8(&request)?
        .lines()
        .next()
        .ok_or("metrics request has no request line")?;
    let path = first
        .split_whitespace()
        .nth(1)
        .ok_or("metrics request line has no path")?;
    let snapshot = metrics.read().expect("metrics lock poisoned").clone();
    let (status, content_type, body) = match path {
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", snapshot.render()),
        "/healthz" => ("200 OK", "text/plain", "ok\n".into()),
        "/readyz" if snapshot.bootstrap_ready => ("200 OK", "text/plain", "ready\n".into()),
        "/readyz" => (
            "503 Service Unavailable",
            "text/plain",
            "bootstrapping\n".into(),
        ),
        _ => ("404 Not Found", "text/plain", "not found\n".into()),
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            namespace: fixture::NAMESPACE.into(),
            seed: 42,
            agent_count: 6,
            round_interval: Duration::from_secs(90),
            fault_duration: Duration::from_secs(20),
            convergence_timeout: Duration::from_secs(300),
            release_data: PathBuf::from("/release-data"),
            state_dir: PathBuf::from("/state"),
        }
    }

    #[test]
    fn fleet_layout_must_divide_evenly_and_faults_are_bounded() {
        assert!(config().validate().is_ok());
        let mut invalid = config();
        invalid.agent_count = 5;
        assert!(invalid.validate().is_err());
        let mut invalid = config();
        invalid.fault_duration = invalid.convergence_timeout;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn plans_are_reproducible_and_every_tenth_round_rejects() {
        let mut state = CampaignState::fresh(42);
        let first = plan_round(&state, 6);
        assert_eq!(first.seed, plan_round(&state, 6).seed);
        assert_eq!(first.groups, plan_round(&state, 6).groups);
        assert!(!first.expected_rejection);
        state.round = 9;
        let tenth = plan_round(&state, 6);
        assert!(tenth.expected_rejection);
        assert_eq!(tenth.groups.len(), 1);
    }

    #[test]
    fn metrics_have_fixed_fault_labels_and_no_round_label() {
        let state = CampaignState::fresh(42);
        let mut metrics = Metrics::from_state(&state, 6);
        metrics.active_fault = Some(FaultKind::IoError);
        let text = metrics.render();
        for kind in FaultKind::ALL {
            assert!(text.contains(&format!("kind=\"{}\"", kind.name())));
        }
        assert!(!text.contains("round=\""));
        assert!(text.contains("updatec_soak_fault_active{kind=\"io_error\"} 1"));
    }

    #[test]
    fn state_rejects_a_seed_or_group_layout_change() {
        let config = config();
        let mut state = CampaignState::fresh(config.seed);
        assert!(state.validate(&config).is_ok());
        state.seed += 1;
        assert!(state.validate(&config).is_err());
        state.seed = config.seed;
        state.desired.remove(fixture::SOAK_GROUPS[0]);
        assert!(state.validate(&config).is_err());
    }

    #[test]
    fn signing_secret_is_exact_and_nonempty() {
        let mut secret = Secret {
            type_: Some("Opaque".into()),
            data: Some(
                SIGNING_KEY_FILES
                    .into_iter()
                    .map(|name| (name.into(), ByteString(vec![1])))
                    .collect(),
            ),
            ..Default::default()
        };
        assert!(validate_signing_secret(&secret).is_ok());
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("extra.pk8".into(), ByteString(vec![1]));
        assert!(validate_signing_secret(&secret).is_err());
        secret.data.as_mut().unwrap().remove("extra.pk8");
        secret
            .data
            .as_mut()
            .unwrap()
            .insert(SIGNING_KEY_FILES[0].into(), ByteString(Vec::new()));
        assert!(validate_signing_secret(&secret).is_err());
    }
}
