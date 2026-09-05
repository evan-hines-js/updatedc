//! Resident, seeded release campaigns for the permanent chaos lab.
//!
//! One controller owns the complete campaign transaction: choose a release, state the expected
//! fleet result, apply the typed deployment, inject one bounded Chaos Mesh fault, wait for exact
//! convergence (or an expected rejection), recover, persist the result, and expose aggregate
//! metrics. Recovery always publishes a strictly newer valid fixture before starting another
//! round, so process or node loss never asks an agent to violate its downgrade boundary and there
//! is no second ad-hoc recovery path.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, TryLockError};
use std::future::Future;
use std::io::{self, Write};
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
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use updatec::{
    DeploymentSpec, UpdateAgent, UpdateGroup, UpdateGroupSet, UpdateGroupStatus, UpdateRepository,
};

use crate::{agent_resource_name, fixture, NAMESPACE};

const STATE_SCHEMA: u8 = 4;
const BASELINE_VERSION: &str = "1.0.0";
const CAMPAIGN_VERSION_MAJOR: u64 = 1_000_000;
const METRICS_PORT: u16 = 9091;
const METRICS_MAX_REQUEST: usize = 8 * 1024;
const CAMPAIGN_STATE_MAX_BYTES: usize = 64 * 1024;

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
            namespace: env::var("UPDATEC_SOAK_NAMESPACE").unwrap_or_else(|_| NAMESPACE.into()),
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
        if self.namespace != NAMESPACE {
            return Err(format!(
                "soak namespace {:?} disagrees with the shared fixture namespace {:?}",
                self.namespace, NAMESPACE
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

struct CampaignLock {
    _file: File,
}

impl CampaignLock {
    fn try_acquire(config: &Config) -> Result<Option<Self>> {
        fs::create_dir_all(&config.state_dir)?;
        let file = foundation::file::open_lock_file(
            &config.state_dir.join("campaign.lock"),
            foundation::file::LockFileDisposition::OpenOrCreate,
        )?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum FaultKind {
    NetworkPartition,
    IoError,
    AgentKill,
    ControllerKill,
}

struct FaultDescriptor {
    metric_name: &'static str,
    resource_kind: &'static str,
    resource_plural: &'static str,
}

impl FaultKind {
    const ALL: [Self; 4] = [
        Self::NetworkPartition,
        Self::IoError,
        Self::AgentKill,
        Self::ControllerKill,
    ];

    const fn descriptor(self) -> FaultDescriptor {
        match self {
            Self::NetworkPartition => FaultDescriptor {
                metric_name: "network_partition",
                resource_kind: "NetworkChaos",
                resource_plural: "networkchaos",
            },
            Self::IoError => FaultDescriptor {
                metric_name: "io_error",
                resource_kind: "IOChaos",
                resource_plural: "iochaos",
            },
            Self::AgentKill => FaultDescriptor {
                metric_name: "agent_kill",
                resource_kind: "PodChaos",
                resource_plural: "podchaos",
            },
            Self::ControllerKill => FaultDescriptor {
                metric_name: "controller_kill",
                resource_kind: "PodChaos",
                resource_plural: "podchaos",
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignState {
    schema: u8,
    seed: u64,
    round: u64,
    release_generation: u64,
    recovery_target: Option<String>,
    desired: BTreeMap<String, String>,
    campaigns: u64,
    successful_campaigns: u64,
    failed_campaigns: u64,
    release_assignments: u64,
    expected_rejections: u64,
    recoveries: u64,
    forward_recoveries: u64,
    recovery_pending: bool,
    consecutive_failures: u64,
    faults: BTreeMap<FaultKind, u64>,
    fault_failures: BTreeMap<FaultKind, u64>,
    last_success_timestamp: i64,
    last_failure_timestamp: i64,
    last_convergence_seconds: f64,
}

impl CampaignState {
    fn fresh(seed: u64) -> Self {
        Self {
            schema: STATE_SCHEMA,
            seed,
            round: 0,
            release_generation: 0,
            recovery_target: None,
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
            forward_recoveries: 0,
            recovery_pending: false,
            consecutive_failures: 0,
            faults: FaultKind::ALL.into_iter().map(|kind| (kind, 0)).collect(),
            fault_failures: FaultKind::ALL.into_iter().map(|kind| (kind, 0)).collect(),
            last_success_timestamp: 0,
            last_failure_timestamp: 0,
            last_convergence_seconds: 0.0,
        }
    }

    fn load(config: &Config) -> Result<Self> {
        fs::create_dir_all(&config.state_dir)?;
        let path = config.state_path();
        let state = match foundation::file::read_bounded_regular(
            &path,
            CAMPAIGN_STATE_MAX_BYTES,
            foundation::file::FinalSymlink::Refuse,
        ) {
            Ok(bytes) => updated_contracts::bounded::decode(
                &bytes,
                "soak campaign state",
                CAMPAIGN_STATE_MAX_BYTES,
            )
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::fresh(config.seed),
            Err(error) => return Err(error.into()),
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
        let fault_kinds = FaultKind::ALL.into_iter().collect::<BTreeSet<_>>();
        if self.faults.keys().copied().collect::<BTreeSet<_>>() != fault_kinds
            || self.fault_failures.keys().copied().collect::<BTreeSet<_>>() != fault_kinds
        {
            return Err("persisted fault counters do not cover the canonical fault set".into());
        }
        let outcomes = self
            .successful_campaigns
            .checked_add(self.failed_campaigns)
            .ok_or("persisted campaign counters overflow")?;
        if self.round != self.campaigns || self.campaigns != outcomes {
            return Err(format!(
                "persisted campaign counters disagree: round={}, campaigns={}, successes={}, failures={}",
                self.round, self.campaigns, self.successful_campaigns, self.failed_campaigns
            )
            .into());
        }
        let accounted_failures = self
            .recoveries
            .checked_add(u64::from(self.recovery_pending))
            .ok_or("persisted recovery counters overflow")?;
        if self.consecutive_failures > self.failed_campaigns
            || accounted_failures != self.failed_campaigns
        {
            return Err("persisted failure and recovery counters are impossible".into());
        }
        let total_faults = self.faults.values().try_fold(0u64, |total, count| {
            total
                .checked_add(*count)
                .ok_or("persisted fault counters overflow")
        })?;
        let total_fault_failures =
            self.fault_failures
                .values()
                .try_fold(0u64, |total, count| {
                    total
                        .checked_add(*count)
                        .ok_or("persisted fault failure counters overflow")
                })?;
        let maximum_assignment_events = self
            .campaigns
            .checked_add(self.forward_recoveries)
            .ok_or("persisted release assignment event bound overflow")?;
        let maximum_assignments = maximum_assignment_events
            .checked_mul(fixture::SOAK_GROUPS.len() as u64)
            .ok_or("persisted release assignment bound overflow")?;
        let minimum_recovery_assignments = self
            .forward_recoveries
            .checked_mul(fixture::SOAK_GROUPS.len() as u64)
            .and_then(|count| count.checked_add(self.successful_campaigns))
            .ok_or("persisted minimum release assignment bound overflow")?;
        if total_faults < self.successful_campaigns
            || total_faults > self.campaigns
            || total_fault_failures > self.failed_campaigns
            || self.expected_rejections > self.round / 10
            || self.release_generation < self.campaigns
            || self.forward_recoveries > self.release_generation
            || self.forward_recoveries < self.recoveries
            || self.release_assignments < minimum_recovery_assignments
            || self.release_assignments > maximum_assignments
        {
            return Err("persisted campaign aggregate counters are impossible".into());
        }
        if (self.successful_campaigns == 0) != (self.last_success_timestamp == 0)
            || (self.failed_campaigns == 0) != (self.last_failure_timestamp == 0)
            || !self.last_convergence_seconds.is_finite()
            || self.last_convergence_seconds.is_sign_negative()
        {
            return Err(
                "persisted campaign timestamps or convergence duration are impossible".into(),
            );
        }
        for version in self.desired.values() {
            validate_stable_version(version, self.release_generation)?;
        }
        if let Some(target) = &self.recovery_target {
            let version = validate_stable_version(target, self.release_generation)?;
            if version.minor != self.release_generation {
                return Err("persisted recovery target is not the latest allocated release".into());
            }
        }
        Ok(())
    }

    fn persist(&self, config: &Config) -> Result<()> {
        self.validate(config)?;
        let path = config.state_path();
        let bytes = updated_contracts::bounded::encode(
            self,
            "soak campaign state",
            CAMPAIGN_STATE_MAX_BYTES,
        )
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        foundation::durable::atomic_write_managed(&path, ".campaign-state-", &bytes)?;
        Ok(())
    }
}

fn validate_stable_version(raw: &str, release_generation: u64) -> Result<Version> {
    if raw == BASELINE_VERSION {
        return Ok(Version::parse(raw)?);
    }
    let version = Version::parse(raw)
        .map_err(|error| format!("persisted desired version {raw:?} is invalid: {error}"))?;
    if version.major != CAMPAIGN_VERSION_MAJOR
        || version.minor == 0
        || version.minor > release_generation
        || version.patch != 0
        || !version.pre.is_empty()
        || !version.build.is_empty()
    {
        return Err(format!(
            "persisted desired version {raw:?} is not a stable release through generation {release_generation}"
        )
        .into());
    }
    Ok(version)
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
    let fault = fault_for_round(state.seed, round);
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

fn fault_for_round(seed: u64, round: u64) -> FaultKind {
    debug_assert!(round > 0);
    let cycle = (round - 1) / FaultKind::ALL.len() as u64;
    let offset = ((round - 1) % FaultKind::ALL.len() as u64) as usize;
    let mut rng = seed ^ cycle.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    let mut faults = FaultKind::ALL;
    for index in (1..faults.len()).rev() {
        let selected = (splitmix64(&mut rng) as usize) % (index + 1);
        faults.swap(index, selected);
    }
    faults[offset]
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
    round_seed: u64,
    state: CampaignState,
    fleet_expected_nodes: usize,
    fleet_converged_nodes: usize,
    active_fault: Option<FaultKind>,
}

impl Metrics {
    fn from_state(state: &CampaignState, expected_nodes: usize) -> Self {
        Self {
            started_timestamp: Utc::now().timestamp(),
            bootstrap_ready: false,
            campaign_healthy: false,
            round_seed: 0,
            state: state.clone(),
            fleet_expected_nodes: expected_nodes,
            fleet_converged_nodes: 0,
            active_fault: None,
        }
    }

    fn sync_state(&mut self, state: &CampaignState) {
        self.state = state.clone();
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
        metric(&mut output, "updatec_soak_round", self.state.round);
        metric(
            &mut output,
            "updatec_soak_release_generation",
            self.state.release_generation,
        );
        metric(&mut output, "updatec_soak_round_seed", self.round_seed);
        metric(
            &mut output,
            "updatec_soak_campaigns_total",
            self.state.campaigns,
        );
        metric(
            &mut output,
            "updatec_soak_successful_campaigns_total",
            self.state.successful_campaigns,
        );
        metric(
            &mut output,
            "updatec_soak_failed_campaigns_total",
            self.state.failed_campaigns,
        );
        metric(
            &mut output,
            "updatec_soak_release_assignments_total",
            self.state.release_assignments,
        );
        metric(
            &mut output,
            "updatec_soak_expected_rejections_total",
            self.state.expected_rejections,
        );
        metric(
            &mut output,
            "updatec_soak_recoveries_total",
            self.state.recoveries,
        );
        metric(
            &mut output,
            "updatec_soak_forward_recoveries_total",
            self.state.forward_recoveries,
        );
        metric(
            &mut output,
            "updatec_soak_recovery_pending",
            u8::from(self.state.recovery_pending),
        );
        metric(
            &mut output,
            "updatec_soak_forward_recovery_pending",
            u8::from(self.state.recovery_target.is_some()),
        );
        metric(
            &mut output,
            "updatec_soak_consecutive_failures",
            self.state.consecutive_failures,
        );
        metric(
            &mut output,
            "updatec_soak_last_success_timestamp_seconds",
            self.state.last_success_timestamp,
        );
        metric(
            &mut output,
            "updatec_soak_last_failure_timestamp_seconds",
            self.state.last_failure_timestamp,
        );
        metric(
            &mut output,
            "updatec_soak_last_convergence_seconds",
            self.state.last_convergence_seconds,
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
                kind.descriptor().metric_name,
                u8::from(active)
            ));
            output.push_str(&format!(
                "updatec_soak_faults_total{{kind=\"{}\"}} {}\n",
                kind.descriptor().metric_name,
                self.state.faults[&kind]
            ));
            output.push_str(&format!(
                "updatec_soak_fault_failures_total{{kind=\"{}\"}} {}\n",
                kind.descriptor().metric_name,
                self.state.fault_failures[&kind]
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
    release_data: PathBuf,
}

#[derive(Clone, Copy)]
enum CandidateKind {
    Valid,
    Corrupt,
}

fn campaign_version(generation: u64) -> Version {
    Version::new(CAMPAIGN_VERSION_MAJOR, generation, 0)
}

impl ReleaseCatalog {
    async fn load(config: &Config) -> Result<Self> {
        let ready = config.release_data.join("ready");
        if !ready.is_file() {
            return Err(format!("release repository is not ready at {}", ready.display()).into());
        }
        let platform = foundation::platform::platform_key();
        let root_json = String::from_utf8(
            updated_tuf::repo::root_bytes(&config.release_data.join("repository")).await?,
        )?;
        let catalog = Self {
            platform,
            root_json,
            release_data: config.release_data.clone(),
        };
        catalog
            .app_sha(BASELINE_VERSION)
            .await
            .map_err(|error| format!("release catalog has no usable baseline: {error}"))?;
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
        Ok(updated_tuf::repo::target_sha256(&self.release_data.join("repository"), target).await?)
    }

    async fn target_sha_if_present(&self, target: &str) -> Result<Option<String>> {
        Ok(updated_tuf::repo::target_sha256_if_present(
            &self.release_data.join("repository"),
            target,
        )
        .await?)
    }

    fn deployment(&self, group: &str, version: &str, sha: &str) -> DeploymentSpec {
        fixture::deployment(group, version, &self.platform, sha, &self.root_json)
    }

    async fn ensure_candidate(
        &self,
        generation: u64,
        kind: CandidateKind,
    ) -> Result<(String, String)> {
        let version = campaign_version(generation).to_string();
        let target = format!("products/app/stable/{version}/{}/app", self.platform);
        if let Some(sha) = self.target_sha_if_present(&target).await? {
            return Ok((version, sha));
        }
        let source = self.release_data.join("soak-fixtures").join(&version);
        fs::create_dir_all(source.join("bin"))?;
        fs::create_dir_all(source.join("config"))?;
        let app = source.join("bin/app");
        match kind {
            CandidateKind::Valid => {
                let artifact = if generation.is_multiple_of(2) {
                    "stateful-like"
                } else {
                    "sampleapp"
                };
                fs::copy(format!("/usr/local/bin/{artifact}"), &app)?;
            }
            CandidateKind::Corrupt => fs::write(
                &app,
                format!("intentionally corrupt soak release {version}\n"),
            )?,
        }
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

struct FaultExecution {
    injected: bool,
    result: Result<()>,
}

impl Campaign {
    async fn bootstrap(
        client: Client,
        config: Config,
        metrics: Arc<RwLock<Metrics>>,
        state: &mut CampaignState,
    ) -> Result<Self> {
        let catalog = ReleaseCatalog::load(&config).await?;
        ensure_signing_secret(&client, &config).await?;
        let campaign = Self {
            client,
            config,
            catalog,
            metrics,
        };
        if state.release_generation == 0 && state.recovery_target.is_none() {
            ensure_control_resources(&campaign.client, &campaign.config, &campaign.catalog, state)
                .await?;
            cleanup_faults(&campaign.client, &campaign.config, &campaign.metrics).await?;
            campaign.wait_for_fleet().await?;
            campaign.wait_converged(&state.desired).await?;
        } else {
            campaign.recover_forward(state).await?;
        }
        {
            let mut metrics = campaign.metrics.write().expect("metrics lock poisoned");
            metrics.bootstrap_ready = true;
            metrics.campaign_healthy = true;
            metrics.sync_state(state);
        }
        Ok(campaign)
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

    async fn reserve_candidate(
        &self,
        state: &mut CampaignState,
        kind: CandidateKind,
    ) -> Result<(String, String)> {
        state.release_generation = state
            .release_generation
            .checked_add(1)
            .ok_or("release generation overflow")?;
        state.persist(&self.config)?;
        self.catalog
            .ensure_candidate(state.release_generation, kind)
            .await
    }

    async fn recover_forward(&self, state: &mut CampaignState) -> Result<()> {
        cleanup_faults(&self.client, &self.config, &self.metrics).await?;
        let generation = if let Some(target) = &state.recovery_target {
            validate_stable_version(target, state.release_generation)?.minor
        } else {
            state.release_generation = state
                .release_generation
                .checked_add(1)
                .ok_or("release generation overflow")?;
            let target = campaign_version(state.release_generation).to_string();
            state.recovery_target = Some(target);
            state.persist(&self.config)?;
            self.metrics
                .write()
                .expect("metrics lock poisoned")
                .sync_state(state);
            state.release_generation
        };
        let (version, _sha) = self
            .catalog
            .ensure_candidate(generation, CandidateKind::Valid)
            .await?;
        let mut forward = state.clone();
        for group in fixture::SOAK_GROUPS {
            forward.desired.insert(group.into(), version.clone());
        }
        ensure_control_resources(&self.client, &self.config, &self.catalog, &forward).await?;
        self.wait_for_fleet().await?;
        let duration = self.wait_converged(&forward.desired).await?;
        forward.release_assignments = forward
            .release_assignments
            .checked_add(fixture::SOAK_GROUPS.len() as u64)
            .ok_or("release assignment counter overflow")?;
        forward.forward_recoveries = forward
            .forward_recoveries
            .checked_add(1)
            .ok_or("forward recovery counter overflow")?;
        forward.recovery_target = None;
        forward.last_convergence_seconds = duration.as_secs_f64();
        forward.persist(&self.config)?;
        *state = forward;
        println!("[soak] fleet recovered forward onto generation {generation}");
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
            plan.fault.descriptor().metric_name,
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
        let (version, sha) = self.reserve_candidate(state, CandidateKind::Valid).await?;
        for group in &plan.groups {
            self.patch_group(group, self.catalog.deployment(group, &version, &sha))
                .await?;
            desired.insert(group.clone(), version.clone());
            state.release_assignments += 1;
        }
        let duration = self
            .run_under_fault(state, plan, self.wait_converged(&desired))
            .await?;
        state.last_convergence_seconds = duration.as_secs_f64();
        state.desired = desired;
        Ok(())
    }

    async fn run_rejection_round(&self, state: &mut CampaignState, plan: &RoundPlan) -> Result<()> {
        let group = plan
            .groups
            .first()
            .expect("a rejection round has one group");
        let (bad_version, bad_sha) = self
            .reserve_candidate(state, CandidateKind::Corrupt)
            .await?;
        self.patch_group(
            group,
            self.catalog.deployment(group, &bad_version, &bad_sha),
        )
        .await?;
        state.release_assignments += 1;
        let stable = state.desired.clone();
        self.run_under_fault(state, plan, self.wait_rejected(group, &stable))
            .await?;
        state.expected_rejections += 1;

        let recovery_version = state
            .desired
            .get(group)
            .ok_or_else(|| format!("no stable version for {group}"))?
            .clone();
        let recovery_sha = self.catalog.app_sha(&recovery_version).await?;
        self.patch_group(
            group,
            self.catalog
                .deployment(group, &recovery_version, &recovery_sha),
        )
        .await?;
        state.release_assignments += 1;
        let duration = self.wait_converged(&state.desired).await?;
        state.last_convergence_seconds = duration.as_secs_f64();
        Ok(())
    }

    async fn run_under_fault<T, F>(
        &self,
        state: &mut CampaignState,
        plan: &RoundPlan,
        assertion: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        // `join!` deliberately waits for both sides. `try_join!` cancels the still-running future
        // after the first error, which can abandon a successfully injected Chaos Mesh object and
        // turn a bounded fault into an unbounded one.
        let (assertion, fault) = tokio::join!(assertion, self.inject_fault(plan));
        if fault.injected {
            *state
                .faults
                .get_mut(&plan.fault)
                .expect("every fault kind has a durable counter") += 1;
        }
        if fault.result.is_err() {
            *state
                .fault_failures
                .get_mut(&plan.fault)
                .expect("every fault kind has a durable failure counter") += 1;
        }
        match (assertion, fault.result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(assertion), Err(fault)) => Err(format!(
                "round assertion failed: {assertion}; fault lifecycle also failed: {fault}"
            )
            .into()),
        }
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
                        if agent_is_converged(&agent, group, expected) {
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
            let rejected = resource
                .metadata
                .generation
                .zip(resource.status.as_ref())
                .is_some_and(|(generation, status)| status_observed_rejection(status, generation));
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
            if !agent_is_converged(&agent, group, expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn inject_fault(&self, plan: &RoundPlan) -> FaultExecution {
        let name = format!("{}{}", fixture::SOAK_CHAOS_NAME_PREFIX, plan.round);
        let (api, object) = match self.fault_object(plan, &name).await {
            Ok(value) => value,
            Err(error) => {
                return FaultExecution {
                    injected: false,
                    result: Err(error),
                };
            }
        };
        {
            let mut metrics = self.metrics.write().expect("metrics lock poisoned");
            metrics.active_fault = Some(plan.fault);
        }
        let mut injected = false;
        let result = async {
            api.create(&PostParams::default(), &object).await?;
            wait_chaos_injected(&api, &name).await?;
            injected = true;
            println!(
                "[soak] {} injected by Chaos Mesh",
                plan.fault.descriptor().metric_name
            );
            tokio::time::sleep(self.config.fault_duration).await;
            delete_dynamic(&api, &name).await?;
            println!("[soak] {} recovered", plan.fault.descriptor().metric_name);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        self.metrics
            .write()
            .expect("metrics lock poisoned")
            .active_fault = None;
        if result.is_err() {
            let _ = delete_dynamic(&api, &name).await;
        }
        FaultExecution { injected, result }
    }

    async fn fault_object(
        &self,
        plan: &RoundPlan,
        name: &str,
    ) -> Result<(Api<DynamicObject>, DynamicObject)> {
        let descriptor = plan.fault.descriptor();
        let api = dynamic_api(
            self.client.clone(),
            &self.config.namespace,
            descriptor.resource_kind,
            descriptor.resource_plural,
        );
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
            "kind": descriptor.resource_kind,
            "metadata": {
                "name": name,
                "namespace": self.config.namespace,
                "labels": {fixture::SOAK_CHAOS_LABEL: fixture::SOAK_CHAOS_VALUE},
            },
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
}

fn status_observed_rejection(status: &UpdateGroupStatus, generation: i64) -> bool {
    status.observed_generation == Some(generation)
        && status.conditions.iter().any(|condition| {
            condition.observed_generation == Some(generation)
                && ((condition.condition_type == updatec::status_contract::READY_CONDITION
                    && condition.status == updatec::status_contract::CONDITION_FALSE
                    && condition.reason == updatec::status_contract::REJECTED_REASON)
                    || (condition.condition_type
                        == updatec::status_contract::DEPLOYMENT_HALTED_CONDITION
                        && condition.status == updatec::status_contract::CONDITION_TRUE
                        && condition.reason
                            == updatec::status_contract::REGRESSION_EVIDENCE_REASON))
        })
}

async fn cleanup_faults(
    client: &Client,
    config: &Config,
    metrics: &Arc<RwLock<Metrics>>,
) -> Result<()> {
    let selector = format!(
        "{}={}",
        fixture::SOAK_CHAOS_LABEL,
        fixture::SOAK_CHAOS_VALUE
    );
    // Derive cleanup from the exhaustive descriptor table and deduplicate shared resources.
    // PodChaos backs both kill variants; new fault kinds cannot silently escape cleanup.
    let resources = FaultKind::ALL
        .into_iter()
        .map(|kind| {
            let descriptor = kind.descriptor();
            (descriptor.resource_kind, descriptor.resource_plural)
        })
        .collect::<BTreeSet<_>>();
    for (resource_kind, resource_plural) in resources {
        let api = dynamic_api(
            client.clone(),
            &config.namespace,
            resource_kind,
            resource_plural,
        );
        let objects = api.list(&ListParams::default().labels(&selector)).await?;
        for object in objects {
            delete_dynamic(&api, &object.name_any()).await?;
        }
    }
    metrics.write().expect("metrics lock poisoned").active_fault = None;
    Ok(())
}

fn agent_hostname(ordinal: usize) -> String {
    format!("agent-{ordinal}")
}

fn agent_is_converged(agent: &UpdateAgent, group: &str, version: &str) -> bool {
    agent.status.as_ref().is_some_and(|status| {
        status.selected_group.as_deref() == Some(group)
            && status.reported_version.as_deref() == Some(version)
            && status.reported_ready == Some(true)
    })
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
    let keys = seed.join("keys");
    let data = if ready.is_file() {
        match read_signing_key_data(&keys) {
            Ok(data) => Some(data),
            Err(error) => {
                println!("[soak] repairing incomplete local signing-key seed: {error}");
                None
            }
        }
    } else {
        None
    };
    let data = if let Some(data) = data {
        data
    } else {
        let repository = seed.join("repository");
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
        let data = read_signing_key_data(&keys)?;
        fs::write(&ready, b"ready")?;
        data
    };
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
        Err(kube::Error::Api(error)) if error.code == 409 => {
            let existing = secrets.get(fixture::SIGNING_SECRET).await?;
            validate_signing_secret(&existing)
        }
        Err(error) => Err(error.into()),
    }
}

fn read_signing_key_data(keys: &std::path::Path) -> Result<BTreeMap<String, ByteString>> {
    let data = updated_tuf::repo::KEY_FILE_NAMES
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                ByteString(updated_tuf::repo::read_signing_key_bytes(&keys.join(name))?),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_signing_key_data(&data)?;
    Ok(data)
}

fn validate_signing_secret(secret: &Secret) -> Result<()> {
    if secret.type_.as_deref() != Some("Opaque") {
        return Err("the TUF signing Secret must have type Opaque".into());
    }
    let data = secret
        .data
        .as_ref()
        .ok_or("the TUF signing Secret has no binary data")?;
    validate_signing_key_data(data)
}

fn validate_signing_key_data(data: &BTreeMap<String, ByteString>) -> Result<()> {
    let actual = data.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = updated_tuf::repo::KEY_FILE_NAMES
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("the TUF signing Secret has non-canonical keys: {actual:?}").into());
    }
    let mut key_ids = BTreeSet::new();
    for (name, value) in data {
        let id = updated_tuf::repo::signing_key_id(&value.0)
            .map_err(|error| format!("the TUF signing Secret's {name} is invalid: {error}"))?;
        key_ids.insert(id);
    }
    if key_ids.len() != data.len() {
        return Err("the TUF signing Secret reuses one private key for multiple roles".into());
    }
    Ok(())
}

async fn ensure_control_resources(
    client: &Client,
    config: &Config,
    catalog: &ReleaseCatalog,
    state: &CampaignState,
) -> Result<()> {
    let sha = catalog.app_sha(BASELINE_VERSION).await?;
    let repository_deployment = catalog.deployment(updatec::DEFAULT_GROUP, BASELINE_VERSION, &sha);
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
        let version = state
            .desired
            .get(name)
            .ok_or_else(|| format!("no persisted desired version for {name}"))?;
        let sha = catalog.app_sha(version).await?;
        groups
            .patch(
                name,
                &apply,
                &Patch::Apply(&fixture::group(
                    name,
                    catalog.deployment(name, version, &sha),
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
    let mut file = foundation::file::open_append_file(&config.journal_path())?;
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(())
}

async fn shutdown_signal() -> Result<&'static str> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => Ok("SIGTERM"),
        _ = interrupt.recv() => Ok("SIGINT"),
    }
}

pub(crate) async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut lock_wait_announced = false;
    let _campaign_lock = loop {
        if let Some(lock) = CampaignLock::try_acquire(&config)? {
            break lock;
        }
        if !lock_wait_announced {
            println!("[soak] another campaign process owns the state lock; waiting without reading or mutating state");
            lock_wait_announced = true;
        }
        tokio::select! {
            biased;
            signal = &mut shutdown => {
                let signal = signal?;
                println!("[soak] received {signal} while waiting for the active campaign process; exiting without competing for cleanup");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    };
    let mut state = CampaignState::load(&config)?;
    state.persist(&config)?;
    let metrics = Arc::new(RwLock::new(Metrics::from_state(&state, config.agent_count)));
    tokio::spawn(serve_metrics(metrics.clone()));
    let client = Client::try_default().await?;
    let campaign = {
        let bootstrap = async {
            loop {
                match Campaign::bootstrap(
                    client.clone(),
                    config.clone(),
                    metrics.clone(),
                    &mut state,
                )
                .await
                {
                    Ok(campaign) => return Ok::<Campaign, Box<dyn std::error::Error>>(campaign),
                    Err(error) => {
                        println!("[soak] bootstrap not ready: {error}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        };
        tokio::pin!(bootstrap);
        tokio::select! {
            biased;
            signal = &mut shutdown => {
                let signal = signal?;
                println!("[soak] received {signal} during bootstrap; removing managed faults before shutdown");
                cleanup_faults(&client, &config, &metrics).await?;
                println!("[soak] graceful shutdown completed with no managed fault active");
                return Ok(());
            }
            campaign = &mut bootstrap => campaign?,
        }
    };
    println!("[soak] release, control resources, and fleet are reconciled");
    if state.recovery_pending {
        state.recovery_pending = false;
        state.recoveries += 1;
        state.persist(&config)?;
        metrics
            .write()
            .expect("metrics lock poisoned")
            .sync_state(&state);
        println!("[soak] completed the pending recovery from the previous process");
    }

    loop {
        let plan = plan_round(&state, config.agent_count);
        let started = Instant::now();
        let (result, shutting_down) = {
            let round = campaign.run_round(&mut state, &plan);
            tokio::pin!(round);
            let mut shutting_down = false;
            let result = tokio::select! {
                biased;
                signal = &mut shutdown => {
                    let signal = signal?;
                    shutting_down = true;
                    println!("[soak] received {signal}; finishing the in-flight fault lifecycle before shutdown");
                    round.as_mut().await
                }
                result = &mut round => result,
            };
            (result, shutting_down)
        };
        state.campaigns += 1;
        state.round = plan.round;
        let failure = match result {
            Ok(()) => {
                state.successful_campaigns += 1;
                state.consecutive_failures = 0;
                state.last_success_timestamp = Utc::now().timestamp();
                None
            }
            Err(error) => {
                let message = error.to_string();
                state.failed_campaigns += 1;
                state.recovery_pending = true;
                state.consecutive_failures += 1;
                state.last_failure_timestamp = Utc::now().timestamp();
                Some(message)
            }
        };
        // The durable aggregate is committed before the append-only detail record or recovery.
        // A crash during either therefore cannot erase a completed round or count it twice.
        state.persist(&config)?;
        {
            let mut metrics = metrics.write().expect("metrics lock poisoned");
            metrics.campaign_healthy = failure.is_none();
            metrics.sync_state(&state);
        }
        append_record(
            &config,
            &plan,
            if failure.is_some() {
                "failed"
            } else {
                "succeeded"
            },
            started.elapsed(),
            failure.as_deref(),
        )?;

        if let Some(message) = failure {
            println!("[soak] round {} failed: {message}", plan.round);
            loop {
                match campaign.recover_forward(&mut state).await {
                    Ok(()) => {
                        state.recovery_pending = false;
                        state.recoveries += 1;
                        state.persist(&config)?;
                        {
                            let mut metrics = metrics.write().expect("metrics lock poisoned");
                            metrics.campaign_healthy = true;
                            metrics.sync_state(&state);
                        }
                        println!("[soak] completed forward-only fleet recovery after failure");
                        break;
                    }
                    Err(error) => {
                        println!("[soak] recovery not ready; refusing another round: {error}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        } else {
            println!("[soak] round {} succeeded", plan.round);
        }
        if shutting_down {
            cleanup_faults(&campaign.client, &campaign.config, &campaign.metrics).await?;
            println!("[soak] graceful shutdown completed with no managed fault active");
            return Ok(());
        }
        tokio::select! {
            biased;
            signal = &mut shutdown => {
                let signal = signal?;
                println!("[soak] received {signal} between rounds; verifying managed faults are absent");
                cleanup_faults(&campaign.client, &campaign.config, &campaign.metrics).await?;
                println!("[soak] graceful shutdown completed with no managed fault active");
                return Ok(());
            }
            _ = tokio::time::sleep(config.round_interval) => {}
        }
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            namespace: NAMESPACE.into(),
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
    fn every_four_rounds_cover_every_fault_exactly_once() {
        let expected = FaultKind::ALL.into_iter().collect::<BTreeSet<_>>();
        for cycle in 0..100 {
            let actual = (1..=FaultKind::ALL.len() as u64)
                .map(|offset| fault_for_round(42, cycle * FaultKind::ALL.len() as u64 + offset))
                .collect::<BTreeSet<_>>();
            assert_eq!(actual, expected, "fault coverage drifted in cycle {cycle}");
        }
    }

    #[test]
    fn campaign_versions_are_strictly_monotonic() {
        let mut previous = Version::parse(BASELINE_VERSION).unwrap();
        for round in 1..=10_000 {
            let current = campaign_version(round);
            assert!(current > previous, "{current} did not follow {previous}");
            previous = current;
        }
    }

    #[test]
    fn metrics_have_fixed_fault_labels_and_no_round_label() {
        let state = CampaignState::fresh(42);
        let mut metrics = Metrics::from_state(&state, 6);
        metrics.active_fault = Some(FaultKind::IoError);
        let text = metrics.render();
        for kind in FaultKind::ALL {
            assert!(text.contains(&format!("kind=\"{}\"", kind.descriptor().metric_name)));
        }
        assert!(!text.contains("round=\""));
        assert!(text.contains("updatec_soak_fault_active{kind=\"io_error\"} 1"));
    }

    #[test]
    fn fault_descriptors_are_complete_and_cleanup_resources_are_derived() {
        let descriptors = FaultKind::ALL.map(|kind| {
            let descriptor = kind.descriptor();
            (
                descriptor.metric_name,
                descriptor.resource_kind,
                descriptor.resource_plural,
            )
        });
        assert_eq!(
            descriptors,
            [
                ("network_partition", "NetworkChaos", "networkchaos"),
                ("io_error", "IOChaos", "iochaos"),
                ("agent_kill", "PodChaos", "podchaos"),
                ("controller_kill", "PodChaos", "podchaos"),
            ]
        );
        assert_eq!(
            descriptors
                .into_iter()
                .map(|(_, kind, plural)| (kind, plural))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("IOChaos", "iochaos"),
                ("NetworkChaos", "networkchaos"),
                ("PodChaos", "podchaos"),
            ])
        );
    }

    #[test]
    fn restart_serialization_preserves_every_aggregate_metric() {
        let config = config();
        let mut state = CampaignState::fresh(config.seed);
        state.round = 1;
        state.release_generation = 1;
        state.campaigns = 1;
        state.successful_campaigns = 1;
        state.release_assignments = 1;
        state.last_success_timestamp = 1;
        state.last_convergence_seconds = 12.5;
        state
            .desired
            .insert(fixture::SOAK_GROUPS[0].into(), "1000000.1.0".into());
        *state.faults.get_mut(&FaultKind::IoError).unwrap() = 1;

        let restored: CampaignState =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        restored.validate(&config).unwrap();
        let rendered = Metrics::from_state(&restored, config.agent_count).render();
        assert!(rendered.contains("updatec_soak_campaigns_total 1\n"));
        assert!(rendered.contains("updatec_soak_release_generation 1\n"));
        assert!(rendered.contains("updatec_soak_faults_total{kind=\"io_error\"} 1\n"));
        assert!(rendered.contains("updatec_soak_last_convergence_seconds 12.5\n"));
    }

    #[test]
    fn persisted_state_round_trips_through_the_durable_atomic_path() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.state_dir = directory.path().into();
        let mut state = CampaignState::fresh(config.seed);
        state.round = 1;
        state.release_generation = 1;
        state.campaigns = 1;
        state.successful_campaigns = 1;
        state.release_assignments = 1;
        state.last_success_timestamp = 1;
        state
            .desired
            .insert(fixture::SOAK_GROUPS[0].into(), "1000000.1.0".into());
        *state.faults.get_mut(&FaultKind::IoError).unwrap() = 1;

        state.persist(&config).unwrap();
        let restored = CampaignState::load(&config).unwrap();

        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(state).unwrap()
        );
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".campaign-state-")
        }));
    }

    #[test]
    fn campaign_state_is_bounded_and_cannot_redirect_its_reader() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.state_dir = directory.path().into();
        std::fs::write(
            config.state_path(),
            vec![b' '; CAMPAIGN_STATE_MAX_BYTES + 1],
        )
        .unwrap();
        assert!(CampaignState::load(&config).is_err());

        std::fs::remove_file(config.state_path()).unwrap();
        let outside = directory.path().join("outside");
        std::fs::write(
            &outside,
            updated_contracts::bounded::encode(
                &CampaignState::fresh(config.seed),
                "soak campaign state",
                CAMPAIGN_STATE_MAX_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, config.state_path()).unwrap();
        assert!(CampaignState::load(&config).is_err());
    }

    #[test]
    fn campaign_state_has_exactly_one_process_writer() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.state_dir = directory.path().into();

        let owner = CampaignLock::try_acquire(&config).unwrap().unwrap();
        assert!(CampaignLock::try_acquire(&config).unwrap().is_none());
        drop(owner);
        assert!(CampaignLock::try_acquire(&config).unwrap().is_some());

        let lock = config.state_dir.join("campaign.lock");
        std::fs::remove_file(&lock).unwrap();
        let redirected = config.state_dir.join("redirected");
        std::fs::write(&redirected, b"must remain ordinary state").unwrap();
        std::os::unix::fs::symlink(&redirected, &lock).unwrap();
        assert!(CampaignLock::try_acquire(&config).is_err());
        assert_eq!(
            std::fs::read(&redirected).unwrap(),
            b"must remain ordinary state"
        );
    }

    #[cfg(unix)]
    #[test]
    fn campaign_journal_cannot_redirect_its_append_through_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config();
        config.state_dir = directory.path().into();
        let outside = directory.path().join("outside");
        std::fs::write(&outside, b"must remain ordinary state").unwrap();
        std::os::unix::fs::symlink(&outside, config.journal_path()).unwrap();
        let state = CampaignState::fresh(config.seed);
        let plan = plan_round(&state, config.agent_count);

        assert!(append_record(&config, &plan, "success", Duration::ZERO, None).is_err());
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"must remain ordinary state"
        );
    }

    #[test]
    fn rejection_evidence_accepts_the_only_two_controller_verdicts_for_current_generation() {
        let condition = |condition_type: &str, status: &str, reason: &str, generation: i64| {
            updatec::ResourceCondition {
                condition_type: condition_type.into(),
                status: status.into(),
                reason: reason.into(),
                message: String::new(),
                observed_generation: Some(generation),
                last_transition_time: String::new(),
            }
        };
        for verdict in [
            condition(
                updatec::status_contract::READY_CONDITION,
                updatec::status_contract::CONDITION_FALSE,
                updatec::status_contract::REJECTED_REASON,
                7,
            ),
            condition(
                updatec::status_contract::DEPLOYMENT_HALTED_CONDITION,
                updatec::status_contract::CONDITION_TRUE,
                updatec::status_contract::REGRESSION_EVIDENCE_REASON,
                7,
            ),
        ] {
            let status = UpdateGroupStatus {
                observed_generation: Some(7),
                conditions: vec![verdict],
                ..Default::default()
            };
            assert!(status_observed_rejection(&status, 7));
            assert!(!status_observed_rejection(&status, 8));
        }

        let status = UpdateGroupStatus {
            observed_generation: Some(7),
            conditions: vec![condition(
                updatec::status_contract::DEPLOYMENT_HALTED_CONDITION,
                updatec::status_contract::CONDITION_FALSE,
                "NoRegression",
                7,
            )],
            ..Default::default()
        };
        assert!(!status_observed_rejection(&status, 7));
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
    fn state_rejects_impossible_counters_fault_sets_and_desired_versions() {
        let config = config();
        let mut state = CampaignState::fresh(config.seed);
        state.campaigns = 1;
        assert!(state.validate(&config).is_err());

        let mut state = CampaignState::fresh(config.seed);
        state.faults.remove(&FaultKind::IoError);
        assert!(state.validate(&config).is_err());

        let mut valid = CampaignState::fresh(config.seed);
        valid.round = 1;
        valid.release_generation = 1;
        valid.campaigns = 1;
        valid.successful_campaigns = 1;
        valid.release_assignments = 1;
        valid.last_success_timestamp = 1;
        *valid.faults.get_mut(&FaultKind::IoError).unwrap() = 1;
        assert!(valid.validate(&config).is_ok());

        let mut impossible = valid.clone();
        *impossible.faults.get_mut(&FaultKind::IoError).unwrap() = 2;
        assert!(impossible.validate(&config).is_err());
        let mut impossible = valid.clone();
        *impossible.faults.get_mut(&FaultKind::IoError).unwrap() = 0;
        assert!(impossible.validate(&config).is_err());
        let mut impossible = valid.clone();
        *impossible
            .fault_failures
            .get_mut(&FaultKind::IoError)
            .unwrap() = 1;
        assert!(impossible.validate(&config).is_err());
        let mut impossible = valid.clone();
        impossible.expected_rejections = 1;
        assert!(impossible.validate(&config).is_err());
        let mut impossible = valid;
        impossible.release_assignments = 0;
        assert!(impossible.validate(&config).is_err());

        assert!(validate_stable_version(BASELINE_VERSION, 0).is_ok());
        assert!(validate_stable_version("1000000.1.0", 1).is_ok());
        assert!(validate_stable_version("1000000.10.0", 10).is_ok());
        assert!(validate_stable_version("1000000.11.0", 10).is_err());
        assert!(validate_stable_version("999999.1.0", 1).is_err());
    }

    #[test]
    fn an_observed_rejection_remains_valid_when_its_recovery_fails() {
        let config = config();
        let mut state = CampaignState::fresh(config.seed);
        state.round = 10;
        state.release_generation = 10;
        state.campaigns = 10;
        state.failed_campaigns = 10;
        state.recoveries = 9;
        state.forward_recoveries = 9;
        state.recovery_pending = true;
        state.consecutive_failures = 10;
        state.release_assignments = 29;
        state.expected_rejections = 1;
        state.last_failure_timestamp = 1;
        for version in state.desired.values_mut() {
            *version = "1000000.9.0".into();
        }
        *state.faults.get_mut(&FaultKind::IoError).unwrap() = 1;

        state.validate(&config).unwrap();
    }

    #[test]
    fn forward_recovery_is_newer_than_the_failed_round_and_resumable() {
        let config = config();
        let mut recovered = CampaignState::fresh(config.seed);
        recovered.round = 1;
        recovered.campaigns = 1;
        recovered.failed_campaigns = 1;
        recovered.recoveries = 1;
        recovered.forward_recoveries = 1;
        recovered.release_generation = 2;
        recovered.release_assignments = fixture::SOAK_GROUPS.len() as u64;
        recovered.consecutive_failures = 1;
        recovered.last_failure_timestamp = 1;
        for version in recovered.desired.values_mut() {
            *version = "1000000.2.0".into();
        }
        recovered.validate(&config).unwrap();

        let mut pending = recovered;
        pending.round = 2;
        pending.campaigns = 2;
        pending.failed_campaigns = 2;
        pending.recovery_pending = true;
        pending.release_generation = 3;
        pending.recovery_target = Some("1000000.3.0".into());
        pending.consecutive_failures = 2;
        pending.validate(&config).unwrap();

        pending.recovery_target = Some("1000000.2.0".into());
        assert!(pending.validate(&config).is_err());
    }

    #[tokio::test]
    async fn signing_secret_is_exact_and_cryptographically_valid() {
        let directory = tempfile::tempdir().unwrap();
        updated_tuf::repo::generate_keys(directory.path())
            .await
            .unwrap();
        let mut secret = Secret {
            type_: Some("Opaque".into()),
            data: Some(
                updated_tuf::repo::KEY_FILE_NAMES
                    .into_iter()
                    .map(|name| {
                        (
                            name.into(),
                            ByteString(std::fs::read(directory.path().join(name)).unwrap()),
                        )
                    })
                    .collect(),
            ),
            ..Default::default()
        };
        assert_eq!(
            read_signing_key_data(directory.path()).unwrap().len(),
            updated_tuf::repo::KEY_FILE_NAMES.len()
        );
        std::fs::write(directory.path().join("targets.pk8"), []).unwrap();
        assert!(read_signing_key_data(directory.path()).is_err());
        assert!(validate_signing_secret(&secret).is_ok());
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("extra.pk8".into(), ByteString(vec![1]));
        assert!(validate_signing_secret(&secret).is_err());
        secret.data.as_mut().unwrap().remove("extra.pk8");
        let targets = secret.data.as_ref().unwrap()["targets.pk8"].clone();
        let root = secret.data.as_ref().unwrap()["root.pk8"].clone();
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("targets.pk8".into(), root);
        assert!(validate_signing_secret(&secret).is_err());
        secret
            .data
            .as_mut()
            .unwrap()
            .insert("targets.pk8".into(), targets);
        secret.data.as_mut().unwrap().insert(
            updated_tuf::repo::KEY_FILE_NAMES[0].into(),
            ByteString(b"not a private key".to_vec()),
        );
        assert!(validate_signing_secret(&secret).is_err());
    }
}
