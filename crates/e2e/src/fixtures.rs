//! Shared test fixtures: the `Node` agent config builder and version-path helpers,
//! used by the e2e scenario runner and the standalone kill fuzzer alike.

use crate::harness::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/app-{v}{}", ctx.exe))
}

/// A TOML literal string (single-quoted, no escaping) — safe for Windows paths.
fn lit(s: &str) -> String {
    format!("'{s}'")
}
/// Writes a scenario's config file and yields an agent command. The disposable agent owns the
/// update policy and invokes the release's reconciler. Nothing here launches a workload: that is the
/// reconciler's job, and [`Node::workload`] is how a scenario asks for one.
#[derive(Clone)]
pub struct Node {
    routing_base_url: String,
    release_base_url: Option<String>,
    agent_bin: PathBuf,
    server_bin: PathBuf,
    dir: PathBuf,
    product: String,
    pub install_root: PathBuf,
    seed_binary: PathBuf,
    check_interval: Option<String>,
    health_grace: Option<String>,
    health_successes: u32,
    confirmation_window: Option<String>,
    /// The mode of the one signed reconciler every scenario runs. `inert` records and succeeds; a
    /// scenario selects its own mode exactly once (see [`Node::mode`]).
    lifecycle_mode: String,
    seed_application: bool,
}

/// The mode the reconciler starts in: record the invocation and succeed. There is one reconciler
/// implementation in this harness, so a scenario can never assert against an operation vocabulary
/// the agent does not speak.
const INERT: &str = "inert";

/// A scenario that deliberately crashes a candidate while it is unconfirmed may spend two full
/// positive-event waits arranging that crash. Keep the confirmation deadline beyond those waits,
/// plus one convergence window, so load can delay the setup without changing the state under test.
/// The scenario never waits for this deadline; it forces the next boot immediately.
const HELD_UNCONFIRMED_SECONDS: u64 = EVENT_TIMEOUT * 2 + CONVERGE_TIMEOUT;

/// The agent state directory — every boot-time input: node config, enrollment bundle, private
/// key, persisted assignment — for a scenario rooted at `dir`.
///
/// A free function because [`crate::harness::node_paths`] needs the same fact without a `Node` in
/// hand, and two spellings of one directory is how a scenario comes to assert on a file nothing
/// writes.
pub fn state_dir(dir: &std::path::Path) -> PathBuf {
    dir.join("agent-state")
}

impl Node {
    /// A node stack for `product`, fed by the repo under `dir` served at `srv`.
    pub fn new(ctx: &Ctx, dir: &Path, srv: &str, product: &str) -> Self {
        // Every seeded predecessor is the version-agnostic sample release at 1.0.0; its identity
        // comes from the bundle config the publisher writes, never from the bytes.
        let seed_binary = app_v(ctx, "1.0.0");
        let release_base_url = std::fs::read_to_string(dir.join("release-base-url")).ok();
        Node {
            routing_base_url: format!("https://{srv}/"),
            release_base_url,
            agent_bin: ctx.agent.clone(),
            server_bin: ctx.server.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            install_root: dir.join("install"),
            seed_binary,
            check_interval: None,
            health_grace: None,
            health_successes: 1,
            confirmation_window: None,
            lifecycle_mode: INERT.into(),
            seed_application: true,
        }
    }
    /// The reconciler manages the sample application at `address`: `converge` makes the workload
    /// match the supplied payload, `rollback` compensates failed-payload effects, and
    /// `healthcheck` observes it. The agent never touches that process.
    pub fn workload(self, address: &str) -> Self {
        self.mode(&format!("workload={address}"))
    }
    /// [`workload`](Self::workload) with a deterministic fault injected into the application.
    pub fn faulty_workload(self, address: &str, fault: &str) -> Self {
        self.mode(&format!("workload={address},fault={fault}"))
    }
    /// Fail only the candidate; recovery must restore a healthy predecessor.
    pub fn faulty_upgrade(self, address: &str, fault: &str) -> Self {
        self.mode(&format!(
            "workload={address},fault={fault},fault-version=2.0.0"
        ))
    }
    /// [`workload`](Self::workload) whose hook withdraws it from traffic for `drain_millis` before
    /// replacing it — the drain a readiness-aware load balancer needs, performed by the release.
    pub fn draining_workload(self, address: &str, drain_millis: u64) -> Self {
        self.mode(&format!("workload={address},drain={drain_millis}"))
    }
    pub fn local_repository(mut self) -> Self {
        self.routing_base_url = format!("{}/", self.dir.join("routing-repo").display());
        self.release_base_url = Some(format!("{}/", self.dir.join("release-repo").display()));
        self
    }
    pub fn check_interval(mut self, s: &str) -> Self {
        self.check_interval = Some(s.into());
        self
    }
    pub fn health_grace(mut self, s: &str) -> Self {
        self.health_grace = Some(s.into());
        self
    }
    pub fn health_successes(mut self, successes: u32) -> Self {
        self.health_successes = successes;
        self
    }
    pub fn confirmation_window(mut self, s: &str) -> Self {
        self.confirmation_window = Some(s.into());
        self
    }
    /// Keep a candidate unconfirmed while a crash/rollback scenario arranges its next boot.
    ///
    /// This owns the relationship between the harness's wait ceilings and the confirmation window;
    /// individual scenarios must not copy a duration that can expire during their own setup.
    pub fn hold_unconfirmed(mut self) -> Self {
        self.confirmation_window = Some(format!("{HELD_UNCONFIRMED_SECONDS}s"));
        self
    }
    /// Select the reconciler's mode (see `crate::fixture`). A scenario selects it exactly once: two
    /// mode-selecting calls in one builder chain would leave the last one silently winning and the
    /// earlier one's intent unmet.
    pub fn mode(mut self, mode: &str) -> Self {
        assert_eq!(
            self.lifecycle_mode, INERT,
            "a scenario selects its node reconciler's mode exactly once"
        );
        self.lifecycle_mode = mode.into();
        self
    }
    /// Start with only the agent and no installed release: the agent must cold-install
    /// the first trusted application and converge it through the reconciler's `converge`.
    pub fn cold_install(mut self) -> Self {
        self.seed_application = false;
        self
    }

    /// The agent's state directory for this scenario.
    pub fn state_dir(&self) -> PathBuf {
        state_dir(&self.dir)
    }

    fn write_config(&self) -> R<PathBuf> {
        let root = crate::fixture::root(&self.dir);
        std::fs::create_dir_all(&root).map_err(str_err)?;
        std::fs::write(root.join("mode"), &self.lifecycle_mode).map_err(str_err)?;
        if self.seed_application {
            self.seed_install()?;
        }
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seconds = |value: Option<&String>, default: u64| -> R<u64> {
            let Some(value) = value else {
                return Ok(default);
            };
            value
                .strip_suffix('s')
                .ok_or_else(|| format!("test duration must use seconds: {value}"))?
                .parse::<u64>()
                .map_err(|error| error.to_string())
        };
        let runtime = updated_contracts::assignment::ManagedRuntime {
            product: self.product.clone(),
            channel: "stable".into(),
            install_root: self.install_root.clone(),
            inputs: updated_contracts::dataflow::InputSelection::default(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 5,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 2,
                inactive_bytes: 1024 * 1024 * 1024,
                inactive_repository_caches: 2,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: seconds(self.check_interval.as_ref(), 15)?,
                health_grace_seconds: seconds(self.health_grace.as_ref(), 10)?,
                health_successes: self.health_successes,
                health_interval_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: seconds(self.confirmation_window.as_ref(), 120)?,
            },
        };
        std::fs::write(
            self.dir.join("assignment-runtime.json"),
            serde_json::to_vec(&runtime).map_err(|error| error.to_string())?,
        )
        .map_err(str_err)?;
        republish_assignment(self, "configured")?;
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        let mut command = Command::new(&self.server_bin);
        command
            .arg("export-enrollment")
            .arg("--repo")
            .arg(self.dir.join("routing-repo"))
            .args(["--assignment", "assignments/agents/agent.json"])
            .args(["--agent-id", "agent"])
            .args(["--routing-base-url", &self.routing_base_url])
            .arg("--output")
            .arg(state_dir.join("enrollment.json"));
        crate::harness::run(command)?;
        let certs = self.dir.join("certs");
        // Steady-state identity is the per-node cert a node mints at enrollment. In this offline,
        // pre-placed scenario the installer supplies the fixture's client leaf directly because the
        // node never reaches `/enroll`.
        std::fs::copy(certs.join("client.crt"), state_dir.join("agent.crt")).map_err(str_err)?;
        std::fs::copy(certs.join("client.key"), state_dir.join("agent.key")).map_err(str_err)?;
        let config = self.dir.join(format!(
            "config-{}.toml",
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &config,
            format!(
                "[enrollment]\nurl = {}\nname = \"agent\"\nca = {}\n",
                lit(if self.routing_base_url.starts_with("https://") {
                    self.routing_base_url.trim_end_matches('/')
                } else {
                    // Offline/file scenarios never reach the network; the URL is unused but must
                    // still be a valid HTTPS string for the secretless mTLS config to load.
                    "https://preplaced.invalid"
                }),
                lit(&certs.join("ca.crt").display().to_string()),
            ),
        )
        .map_err(str_err)?;
        Ok(config)
    }

    #[allow(clippy::disallowed_methods)]
    fn seed_install(&self) -> R {
        // The layout production resolves, not a copy of it: a scenario that plants or reads a
        // file through these paths must exercise the same locations the agent under test uses.
        let paths = updated::config::Paths::resolve(&self.install_root, &self.state_dir());
        if matches!(
            updated::state::read_installed(&paths.installed),
            updated::state::Installed::Present(_)
        ) {
            return Ok(());
        }
        let prepared = self.install_root.join("seed-source");
        std::fs::create_dir_all(prepared.join("bin")).map_err(str_err)?;
        std::fs::create_dir_all(prepared.join("config")).map_err(str_err)?;
        let entrypoint = format!("bin/app{}", if cfg!(windows) { ".exe" } else { "" });
        std::fs::copy(&self.seed_binary, prepared.join(&entrypoint)).map_err(str_err)?;
        std::fs::write(
            prepared.join("config/release.toml"),
            "version = \"1.0.0\"\n",
        )
        .map_err(str_err)?;
        std::fs::create_dir_all(self.install_root.join("state")).map_err(str_err)?;
        crate::fixture::prepare_package(&prepared)?;
        updated::bundle::create_bundle(
            &prepared,
            &paths.download,
            &self.product,
            "1.0.0",
            &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        )
        .map_err(str_err)?;
        let staged = updated::bundle_store::BundleStore::for_app(&paths)
            .install(
                &paths.download,
                &updated::bundle::ExpectedBundle {
                    product: &self.product,
                    version: "1.0.0",
                    platform: &foundation::platform::platform_key(),
                },
            )
            .map_err(str_err)?;
        updated::bundle::write_active(&paths.active_release, &staged).map_err(str_err)?;
        let lineage = updated::state::RepositoryLineage::from_metadata_url(&format!(
            "{}metadata/",
            self.release_base_url()?
        ))
        .map_err(str_err)?;
        updated::state::record_first_install(&paths.installed).map_err(str_err)?;
        // Seed the execution derived from these exact package bytes.
        let execution =
            updated::command_adapter::execution_for(&prepared, &self.product).map_err(str_err)?;
        let installed = updated::state::InstalledState::proven(
            lineage,
            staged,
            crate::harness::sha256_hex(&paths.download)?,
            Box::new(execution),
        );
        let graph_path = self.dir.join("application.json");
        let mut graph: updated_contracts::releases::ReleaseGraph =
            serde_json::from_slice(&std::fs::read(&graph_path).map_err(str_err)?)
                .map_err(str_err)?;
        let package = updated_contracts::artifact::TargetReference {
            path: crate::harness::release_target(
                &self.product,
                "stable",
                "1.0.0",
                &foundation::platform::platform_key(),
                &self.product,
            ),
            sha256: installed.archive_sha256.clone(),
        };
        if let Some(published) = graph.releases.get("1.0.0") {
            if published.package != package {
                return fail("seeded 1.0.0 differs from the published immutable release");
            }
        } else {
            graph.releases.insert(
                "1.0.0".into(),
                updated_contracts::releases::Release {
                    package,
                    installable: false,
                    rollback_from: Default::default(),
                    upgrade_from: Default::default(),
                },
            );
        }
        for (version, release) in &mut graph.releases {
            if updated_contracts::identity::parse_release_version(version)
                > updated_contracts::identity::parse_release_version("1.0.0")
            {
                release.upgrade_from.insert("1.0.0".into());
            }
        }
        std::fs::write(graph_path, serde_json::to_vec(&graph).map_err(str_err)?)
            .map_err(str_err)?;
        updated::state::write_installed(&paths.installed, &installed).map_err(str_err)
    }

    /// An agent command with its persistent state directory supplied by the external supervisor.
    pub fn command(self) -> R<Command> {
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.agent_bin);
        c.env(updated::env::STATE_DIR, state_dir)
            .arg("--config")
            .arg(cfg);
        Ok(c)
    }

    fn release_base_url(&self) -> R<&str> {
        self.release_base_url.as_deref().ok_or_else(|| {
            "release object origin is unavailable; start the repository fixture or select the explicit local repository"
                .into()
        })
    }
}
pub fn target_sha256(server: &Path, dir: &Path, name: &str) -> R<String> {
    let output = Command::new(server)
        .arg("target-sha256")
        .arg("--repo")
        .arg(dir.join("release-repo"))
        .arg("--name")
        .arg(name)
        .output()
        .map_err(str_err)?;
    if !output.status.success() {
        return fail(format!(
            "reading target {name} digest failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|error| error.to_string())?
        .trim()
        .to_string())
}

/// The single builder of the `server publish-assignment` invocation — the signed-assignment format.
/// Both the harness's initial publish and a `Node` republish go through it, so a change to how an
/// assignment is published (a new required flag, a changed marker) lands in exactly one place and
/// the two entry points can never drift. The metadata/targets URLs are the only per-caller inputs
/// (the harness derives them from a listen address; a `Node` from its repository base).
pub fn publish_assignment(
    server: &Path,
    dir: &Path,
    metadata_url: &str,
    targets_url: &str,
    deployment: &str,
) -> R {
    let runtime = dir.join("assignment-runtime.json");
    let mut command = Command::new(server);
    command
        .arg("publish-assignment")
        .arg("--repo")
        .arg(dir.join("routing-repo"))
        .arg("--keys")
        .arg(dir.join("routing-keys"))
        .arg("--release-root")
        .arg(dir.join("release-repo/metadata/root.json"))
        .args(["--name", "assignments/agents/agent.json"])
        .args(["--metadata-url", metadata_url])
        .args(["--targets-url", targets_url])
        .args(["--deployment", deployment])
        .arg("--application")
        .arg(dir.join("application.json"))
        .arg("--runtime")
        .arg(runtime);
    crate::harness::run(command)
}

pub fn republish_assignment(node: &Node, deployment: &str) -> R {
    let release = node.release_base_url()?;
    publish_assignment(
        &node.server_bin,
        &node.dir,
        &format!("{release}metadata/"),
        &format!("{release}targets/"),
        deployment,
    )
}
