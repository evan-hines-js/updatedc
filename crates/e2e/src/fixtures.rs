//! Shared test fixtures: the `Node` launcher+agent config builder and version-path helpers,
//! used by the e2e scenario runner and the standalone kill fuzzer alike.

use crate::harness::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/app-{v}{}", ctx.exe))
}

pub fn agent_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/agent-{v}{}", ctx.exe))
}
/// A TOML literal string (single-quoted, no escaping) — safe for Windows paths.
fn lit(s: &str) -> String {
    format!("'{s}'")
}
/// Writes a scenario's config file and yields a launcher command — the whole node stack. The
/// launcher (`launcher`) decides which agent binary runs; the disposable agent owns the update
/// policy and invokes the release's reconciler. Nothing here launches a workload: that is the
/// reconciler's job, and [`Node::workload`] is how a scenario asks for one.
#[derive(Clone)]
pub struct Node {
    repository_base_url: String,
    agent_bin: PathBuf,
    server_bin: PathBuf,
    platform: String,
    exe: &'static str,
    launcher_bin: PathBuf,
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
    agent_check_interval: Option<String>,
    ready_timeout: Option<String>,
    seed_application: bool,
    /// Override the agent binary the launcher runs (self-update tests supply a
    /// specific version); defaults to the built one.
    agent_override: Option<PathBuf>,
    /// Sign `ordered_install_fallback` into the assignment: a cold node whose exact assigned
    /// bytes prove unusable may descend to the newest healthy target at or below it.
    ordered_install_fallback: bool,
    secrets: Vec<updated_contracts::assignment::SecretReference>,
}

/// The mode the reconciler starts in: record the invocation and succeed. There is one reconciler
/// implementation in this harness, so a scenario can never assert against an operation vocabulary
/// the agent does not speak.
const INERT: &str = "inert";

impl Node {
    /// A node stack for `product`, fed by the repo under `dir` served at `srv`.
    pub fn new(ctx: &Ctx, dir: &Path, srv: &str, product: &str) -> Self {
        // Every seeded predecessor is the version-agnostic sample release at 1.0.0; its identity
        // comes from the bundle config the publisher writes, never from the bytes.
        let seed_binary = app_v(ctx, "1.0.0");
        Node {
            repository_base_url: format!("https://{srv}/"),
            agent_bin: ctx.agent.clone(),
            server_bin: ctx.server.clone(),
            platform: ctx.platkey.clone(),
            exe: ctx.exe,
            launcher_bin: ctx.launcher.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            install_root: dir.join("install"),
            seed_binary,
            check_interval: None,
            health_grace: None,
            health_successes: 1,
            confirmation_window: None,
            lifecycle_mode: INERT.into(),
            agent_check_interval: None,
            ready_timeout: None,
            seed_application: true,
            agent_override: None,
            ordered_install_fallback: false,
            secrets: vec![],
        }
    }
    pub fn secret(mut self, environment: &str, secret: &str, key: &str) -> Self {
        self.secrets
            .push(updated_contracts::assignment::SecretReference {
                environment: environment.into(),
                secret: secret.into(),
                key: key.into(),
            });
        self
    }
    /// Sign ordered-install fallback into the assignment (see the struct field).
    pub fn ordered_install_fallback(mut self) -> Self {
        self.ordered_install_fallback = true;
        self
    }
    /// The reconciler manages the sample application at `address`: its `apply` converges the
    /// workload onto the candidate, its `rollback` onto the predecessor, and its `healthcheck`
    /// observes it. The agent never touches that process.
    pub fn workload(self, address: &str) -> Self {
        self.mode(&format!("workload={address}"))
    }
    /// [`workload`](Self::workload) with a deterministic fault injected into the application.
    pub fn faulty_workload(self, address: &str, fault: &str) -> Self {
        self.mode(&format!("workload={address},fault={fault}"))
    }
    /// [`workload`](Self::workload) whose hook withdraws it from traffic for `drain_millis` before
    /// replacing it — the drain a readiness-aware load balancer needs, performed by the release.
    pub fn draining_workload(self, address: &str, drain_millis: u64) -> Self {
        self.mode(&format!("workload={address},drain={drain_millis}"))
    }
    pub fn local_repository(mut self) -> Self {
        self.repository_base_url = format!("{}/", self.dir.join("repo").display());
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
    pub fn agent_check_interval(mut self, check_interval: &str) -> Self {
        self.agent_check_interval = Some(check_interval.into());
        self
    }
    /// How long a replacement agent has to prove ready before the launcher rolls back.
    pub fn ready_timeout(mut self, secs: &str) -> Self {
        self.ready_timeout = Some(secs.into());
        self
    }
    /// Run this agent binary instead of the default (self-update tests).
    pub fn agent_bin(mut self, path: &Path) -> Self {
        self.agent_override = Some(path.to_path_buf());
        self
    }

    /// Start with only the launcher + agent and no installed release: the agent must cold-install
    /// the first trusted application and converge it through the reconciler's `apply`.
    pub fn cold_install(mut self) -> Self {
        self.seed_application = false;
        self
    }

    /// The launcher's state directory for this scenario.
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("launcher-state")
    }

    /// The reconciler command this node publishes and runs: this driver's own executable in the
    /// selected mode, recording into the scenario's fixture root.
    fn lifecycle_command(&self) -> Vec<String> {
        vec![
            std::env::current_exe()
                .expect("the reconciler fixture must have a current executable")
                .display()
                .to_string(),
            crate::fixture::FLAG.into(),
            crate::fixture::root(&self.dir).display().to_string(),
            self.lifecycle_mode.clone(),
        ]
    }

    /// Materialize a provider `command` into a real executable source tree with a stable
    /// entrypoint, returning `(source_tree, entrypoint, args_to_sign)`. An `sh -c <script>`
    /// command is written out as a `#!/bin/sh` entrypoint so the provider is a genuine bundle,
    /// exactly as an operator would ship one. Shared by the repo publish and the seed staging so
    /// a seeded predecessor's provider is byte-for-byte what its published set installs.
    fn materialize_provider(
        &self,
        kind: &str,
        command: &[String],
    ) -> R<(PathBuf, String, Vec<String>)> {
        let (program, provider_args) = command
            .split_first()
            .ok_or("provider command requires an executable")?;
        let program = resolve_executable(program)?;
        #[cfg(unix)]
        let materialized = if program.file_name().and_then(|name| name.to_str()) == Some("sh")
            && provider_args.first().map(String::as_str) == Some("-c")
            && provider_args.len() == 2
        {
            use std::os::unix::fs::PermissionsExt;
            let tree = self.dir.join(format!("{kind}-provider-source"));
            let published_entrypoint = format!("bin/{kind}");
            std::fs::create_dir_all(tree.join("bin")).map_err(str_err)?;
            let entrypoint = tree.join(&published_entrypoint);
            std::fs::write(&entrypoint, format!("#!/bin/sh\n{}\n", provider_args[1]))
                .map_err(str_err)?;
            let mut permissions = std::fs::metadata(&entrypoint)
                .map_err(str_err)?
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&entrypoint, permissions).map_err(str_err)?;
            (tree, published_entrypoint, Vec::new())
        } else {
            (
                program.clone(),
                format!("bin/{kind}{}", self.exe),
                provider_args.to_vec(),
            )
        };
        #[cfg(not(unix))]
        let materialized = (
            program.clone(),
            format!("bin/{kind}{}", self.exe),
            provider_args.to_vec(),
        );
        Ok(materialized)
    }

    /// Stage a provider bundle into the seeded install's provider store and return the
    /// `ProviderRelease` record it commits under. A seeded predecessor must carry its signed
    /// provider set exactly as a cold-installed node would: the rollback path restores the
    /// predecessor *with its own* providers (they roll back as one signed unit), so a seed that
    /// omitted them leaves the rollback with nothing to replay.
    fn stage_seed_provider(
        &self,
        paths: &updated::config::Paths,
        kind: &str,
        command: &[String],
    ) -> R<updated::state::ProviderRelease> {
        let (source, entrypoint, signed_args) = self.materialize_provider(kind, command)?;
        let product = format!("{}-{kind}", self.product);
        // `materialize_provider` yields either a source *tree* (the `sh -c` case) or a bare
        // executable *file* (the plain-binary case, e.g. the e2e self-invocation). `create_bundle`
        // needs a real tree with the entrypoint at its relative path, so assemble one either way.
        let tree = self.dir.join(format!("{kind}-seed-bundle"));
        let entry_file = tree.join(&entrypoint);
        std::fs::create_dir_all(
            entry_file
                .parent()
                .ok_or("provider entrypoint has no parent")?,
        )
        .map_err(str_err)?;
        let entry_source = if source.is_dir() {
            source.join(&entrypoint)
        } else {
            source.clone()
        };
        std::fs::copy(&entry_source, &entry_file).map_err(str_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&entry_file, std::fs::Permissions::from_mode(0o755))
                .map_err(str_err)?;
        }
        std::fs::create_dir_all(&paths.provider_staging).map_err(str_err)?;
        let download = paths.provider_staging.join(format!("{kind}.download"));
        updated::bundle::create_bundle(
            &tree,
            &download,
            &product,
            "1.0.0",
            &self.platform,
            &entrypoint,
        )
        .map_err(str_err)?;
        let staged = updated::provider::BundleStore::for_lifecycle(paths)
            .install(
                &download,
                &updated::bundle::ExpectedBundle {
                    product: &product,
                    version: "1.0.0",
                    platform: &self.platform,
                },
            )
            .map_err(str_err)?;
        Ok(updated::state::ProviderRelease {
            product,
            release: staged,
            archive_sha256: crate::harness::sha256_hex(&download)?,
            args: signed_args,
            timeout_millis: 5000,
        })
    }

    /// Publish a signed lifecycle provider artifact built from
    /// `command`, returning its release target path, sha256, and the args to sign into the set.
    fn publish_provider(&self, kind: &str, command: &[String]) -> R<(String, String, Vec<String>)> {
        let (published_source, published_entrypoint, signed_args) =
            self.materialize_provider(kind, command)?;
        let provider_product = format!("{}-{kind}", self.product);
        crate::harness::run(
            Command::new(&self.server_bin)
                .arg("publish-provider-artifact")
                .arg("--repo")
                .arg(self.dir.join("repo"))
                .arg("--keys")
                .arg(self.dir.join("keys"))
                .args(["--product", &provider_product, "--version", "1.0.0"])
                .arg("--bundle")
                .arg(format!("{}={}", self.platform, published_source.display()))
                .args(["--entrypoint", &published_entrypoint]),
        )?;
        let provider_path = crate::harness::release_target(
            &provider_product,
            "stable",
            "1.0.0",
            &self.platform,
            &provider_product,
        );
        let provider_sha = target_sha256(&self.server_bin, &self.dir, &provider_path)?;
        Ok((provider_path, provider_sha, signed_args))
    }

    fn write_config(&self) -> R<PathBuf> {
        if self.seed_application {
            self.seed_install()?;
        }
        {
            let mut provider_set = Command::new(&self.server_bin);
            provider_set
                .arg("publish-provider-set")
                .arg("--repo")
                .arg(self.dir.join("repo"))
                .arg("--keys")
                .arg(self.dir.join("keys"))
                .args(["--id", "default"]);
            let (path, sha, signed_args) =
                self.publish_provider("lifecycle", &self.lifecycle_command())?;
            provider_set
                .args(["--provider-path", &path])
                .args(["--provider-sha256", &sha])
                .args(["--provider-timeout-ms", "5000"]);
            for arg in &signed_args {
                provider_set.args(["--provider-arg", arg]);
            }
            crate::harness::run(&mut provider_set)?;
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
            secrets: self.secrets.clone(),
            inputs: std::collections::BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 5,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_agents: 1,
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
                agent_check_interval_seconds: seconds(self.agent_check_interval.as_ref(), 3600)?,
            },
        };
        std::fs::write(
            self.dir.join("assignment-runtime.json"),
            serde_json::to_vec(&runtime).map_err(|error| error.to_string())?,
        )
        .map_err(str_err)?;
        // A marker file (like `desired-app`) carries the fallback opt-in to the assignment
        // publisher, which signs it into every republished assignment doc.
        if self.ordered_install_fallback {
            std::fs::write(self.dir.join("ordered-install-fallback"), []).map_err(str_err)?;
        }
        republish_assignment(self, "configured")?;
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        crate::harness::run(
            Command::new(&self.server_bin)
                .arg("export-enrollment")
                .arg("--repo")
                .arg(self.dir.join("repo"))
                .args(["--assignment", "assignments/agents/agent.json"])
                .args(["--agent-id", "agent"])
                .args(["--routing-base-url", &self.repository_base_url])
                .arg("--output")
                .arg(state_dir.join("enrollment.json")),
        )?;
        let certs = self.dir.join("certs");
        // Steady-state identity is the per-node cert a node mints at enrollment. In this offline,
        // pre-placed scenario the installer supplies it directly (enrollment.json is pre-placed, so
        // the node never reaches the network `/enroll`), so copy the fleet cert in as that identity —
        // the release-server verifies it against the same CA. A live enrollment would mint a distinct
        // per-node leaf; the e2e needs no per-node attribution.
        std::fs::copy(certs.join("client.crt"), state_dir.join("agent.crt")).map_err(str_err)?;
        std::fs::copy(certs.join("client.key"), state_dir.join("agent.key")).map_err(str_err)?;
        let config = self.dir.join(format!(
            "config-{}.toml",
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &config,
            format!(
                "[enrollment]\nurl = {}\nname = \"agent\"\nclient_cert = {}\nclient_key = {}\nca = {}\n",
                lit(if self.repository_base_url.starts_with("https://") {
                    self.repository_base_url.trim_end_matches('/')
                } else {
                    // Offline/file scenarios never reach the network; the URL is unused but must
                    // still be a valid HTTPS string for the secretless mTLS config to load.
                    "https://preplaced.invalid"
                }),
                lit(&certs.join("client.crt").display().to_string()),
                lit(&certs.join("client.key").display().to_string()),
                lit(&certs.join("ca.crt").display().to_string()),
            ),
        )
        .map_err(str_err)?;
        Ok(config)
    }

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
        updated::bundle::create_bundle(
            &prepared,
            &paths.download,
            &self.product,
            "1.0.0",
            &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            &entrypoint,
        )
        .map_err(str_err)?;
        let staged = updated::provider::BundleStore::for_app(&paths)
            .install(
                &paths.download,
                &updated::bundle::ExpectedBundle {
                    product: &self.product,
                    version: "1.0.0",
                    platform: &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                },
            )
            .map_err(str_err)?;
        updated::bundle::write_active(&paths.active_release, &staged).map_err(str_err)?;
        let lineage = updated::state::RepositoryLineage::from_metadata_url(&format!(
            "{}metadata/",
            self.repository_base_url
        ));
        updated::state::enroll(&paths.installed).map_err(str_err)?;
        // Carry the same signed provider set the published assignment references, so the seeded
        // predecessor is faithful to a cold-installed node (install stages its providers). Without
        // this the first update's rollback restores a predecessor with no providers to replay.
        let command = self.lifecycle_command();
        let installed = updated::state::InstalledState::confirmed(
            lineage,
            staged,
            crate::harness::sha256_hex(&paths.download)?,
            Box::new(self.stage_seed_provider(&paths, "lifecycle", &command)?),
        );
        updated::state::write_installed(&paths.installed, &installed).map_err(str_err)
    }

    /// A launcher command: `launcher --state-dir <dir> --config <cfg>
    /// --agent <agent>`. This is the whole node stack — the launcher decides which agent
    /// binary runs, and the agent runs packages.
    pub fn launcher(self) -> R<Command> {
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        let agent = self
            .agent_override
            .clone()
            .unwrap_or_else(|| self.agent_bin.clone());
        let ready_timeout = self.ready_timeout.clone().unwrap_or_else(|| "30".into());
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.launcher_bin);
        c.arg("--state-dir")
            .arg(&state_dir)
            .arg("--config")
            .arg(&cfg)
            .arg("--agent")
            .arg(&agent)
            .arg("--ready-timeout")
            .arg(&ready_timeout)
            .arg("--confirm-timeout")
            .arg("1");
        Ok(c)
    }
}
pub fn target_sha256(server: &Path, dir: &Path, name: &str) -> R<String> {
    let output = Command::new(server)
        .arg("target-sha256")
        .arg("--repo")
        .arg(dir.join("repo"))
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
fn resolve_executable(program: &str) -> R<PathBuf> {
    let path = PathBuf::from(program);
    if path.components().count() > 1 {
        return Ok(path);
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("lifecycle executable {program:?} was not found on PATH"))
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
    let desired = std::fs::read_to_string(dir.join("desired-app")).map_err(str_err)?;
    let mut desired = desired.lines();
    let app_path = desired
        .next()
        .ok_or("desired application path is missing")?;
    let app_sha = desired
        .next()
        .ok_or("desired application hash is missing")?;
    let set_path = "provider-sets/default.json";
    let set_sha = target_sha256(server, dir, set_path)?;
    let runtime = dir.join("assignment-runtime.json");
    let mut command = Command::new(server);
    command
        .arg("publish-assignment")
        .arg("--repo")
        .arg(dir.join("repo"))
        .arg("--keys")
        .arg(dir.join("keys"))
        .args(["--name", "assignments/agents/agent.json"])
        .args(["--metadata-url", metadata_url])
        .args(["--targets-url", targets_url])
        .args(["--deployment", deployment])
        .args(["--application-path", app_path])
        .args(["--application-sha256", app_sha])
        .args(["--provider-set-path", set_path])
        .args(["--provider-set-sha256", &set_sha])
        .arg("--runtime")
        .arg(runtime);
    // The Node builder drops this marker when ordered-install fallback is opted into; it must
    // ride the *initial* assignment (this is the doc a cold node resolves), not only later
    // republishes, or the first install pins the assigned head exactly and cannot descend.
    if dir.join("ordered-install-fallback").exists() {
        command.arg("--ordered-install-fallback");
    }
    crate::harness::run(&mut command)
}

pub fn republish_assignment(node: &Node, deployment: &str) -> R {
    publish_assignment(
        &node.server_bin,
        &node.dir,
        &format!("{}metadata/", node.repository_base_url),
        &format!("{}targets/", node.repository_base_url),
        deployment,
    )
}
