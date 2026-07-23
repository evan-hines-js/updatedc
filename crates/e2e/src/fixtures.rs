//! Shared test fixtures: the `Sup` supervisor/guardian config builder and version-path helpers,
//! used by the e2e scenario runner and the standalone kill fuzzer alike.

use crate::harness::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/app-{v}{}", ctx.exe))
}

/// The `--activate <entrypoint>` publish args for a `custom` (reload-in-place) lifecycle provider:
/// it ships the same script as its `activate` entrypoint, so the supervisor derives reload mode
/// from the artifact. Empty for stop-start deployments and non-lifecycle providers.
fn reload_activate_args(kind: &str, custom: bool, entrypoint: &str) -> Vec<String> {
    if custom && kind == "lifecycle" {
        vec!["--activate".into(), entrypoint.into()]
    } else {
        Vec::new()
    }
}
#[cfg(unix)]
pub fn reexec_app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/reexec-app-{v}{}", ctx.exe))
}
pub fn supervisor_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/supervisor-{v}{}", ctx.exe))
}
/// The managed-app command line (binary path + args) for a scenario config.
pub fn appcmd(app: &Path, args: &[&str]) -> Vec<String> {
    let mut v = vec![app.display().to_string()];
    v.extend(args.iter().map(|s| s.to_string()));
    v
}
/// A TOML literal string (single-quoted, no escaping) — safe for Windows paths.
fn lit(s: &str) -> String {
    format!("'{s}'")
}
/// Writes a scenario's config file and yields a guardian command — the whole tower.
/// The guardian (`bootstrap`) launches the disposable supervisor, which owns the update
/// policy and drives the guardian to run the application. Production launches nothing
/// else; there is no way to run the supervisor standalone.
#[derive(Clone)]
pub struct Sup {
    repository_base_url: String,
    supervisor_bin: PathBuf,
    server_bin: PathBuf,
    platform: String,
    exe: &'static str,
    guardian_bin: PathBuf,
    oneshot_bin: PathBuf,
    dir: PathBuf,
    product: String,
    pub install_root: PathBuf,
    seed_binary: PathBuf,
    args: Vec<String>,
    health_checks: Vec<updated::config::ManagedHealthCheck>,
    check_interval: Option<String>,
    health_grace: Option<String>,
    health_successes: u32,
    confirmation_window: Option<String>,
    retry_after: Option<String>,
    lifecycle_command: Option<Vec<String>>,
    health_command: Option<Vec<String>>,
    custom: bool,
    supervisor_check_interval: Option<String>,
    ready_timeout: Option<String>,
    probe_address: Option<String>,
    seed_application: bool,
    /// Override the supervisor binary the guardian runs (self-update tests supply a
    /// specific version); defaults to the built one.
    supervisor_override: Option<PathBuf>,
    /// Sign `ordered_install_fallback` into the assignment: a cold node whose exact assigned
    /// bytes prove unusable may descend to the newest healthy target at or below it.
    ordered_install_fallback: bool,
}
impl Sup {
    /// The tower managing `command` (the app binary + args) against the repo under
    /// `dir` served at `srv`, for `product`.
    pub fn new(ctx: &Ctx, dir: &Path, srv: &str, product: &str, command: Vec<String>) -> Self {
        let seed_binary = PathBuf::from(command.first().expect("app command requires binary"));
        Sup {
            repository_base_url: format!("https://{srv}/"),
            supervisor_bin: ctx.supervisor.clone(),
            server_bin: ctx.server.clone(),
            platform: ctx.platkey.clone(),
            exe: ctx.exe,
            guardian_bin: ctx.bootstrap.clone(),
            oneshot_bin: ctx.oneshot.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            install_root: dir.join("install"),
            seed_binary,
            args: command.into_iter().skip(1).collect(),
            health_checks: Vec::new(),
            check_interval: None,
            health_grace: None,
            health_successes: 1,
            confirmation_window: None,
            retry_after: None,
            lifecycle_command: None,
            health_command: None,
            custom: false,
            supervisor_check_interval: None,
            ready_timeout: None,
            probe_address: None,
            seed_application: true,
            supervisor_override: None,
            ordered_install_fallback: false,
        }
    }
    /// Sign ordered-install fallback into the assignment (see the struct field).
    pub fn ordered_install_fallback(mut self) -> Self {
        self.ordered_install_fallback = true;
        self
    }
    pub fn readiness_health(self, svc: &str) -> Self {
        self.health_check(
            updated::config::HealthCheckKind::Readiness,
            &format!("http://{svc}/healthz"),
        )
    }
    pub fn health_check(mut self, kind: updated::config::HealthCheckKind, url: &str) -> Self {
        self.health_checks
            .push(updated::config::ManagedHealthCheck {
                kind,
                url: url.into(),
            });
        self
    }
    pub fn guardian_probes(mut self, address: &str) -> Self {
        self.probe_address = Some(address.into());
        self
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
    pub fn retry_after(mut self, s: &str) -> Self {
        self.retry_after = Some(s.into());
        self
    }
    /// Custom activation: the supervisor stops/starts nothing; the lifecycle provider owns
    /// bringing each release into service (placement at first install, an in-place reload — e.g.
    /// SIGHUP — on update). The command is that lifecycle provider.
    pub fn custom(mut self, command: Vec<String>) -> Self {
        self.custom = true;
        self.lifecycle_command = Some(command);
        self
    }
    pub fn lifecycle(mut self, command: Vec<String>) -> Self {
        self.lifecycle_command = Some(command);
        self
    }
    /// Ship a health-check provider: `command` is run as the readiness signal (exit 0 = healthy),
    /// replacing the HTTP probe for this deployment.
    pub fn health_provider(mut self, command: Vec<String>) -> Self {
        self.health_command = Some(command);
        self
    }
    pub fn supervisor_check_interval(mut self, check_interval: &str) -> Self {
        self.supervisor_check_interval = Some(check_interval.into());
        self
    }
    /// How long a replacement supervisor has to prove ready before the guardian rolls back.
    pub fn ready_timeout(mut self, secs: &str) -> Self {
        self.ready_timeout = Some(secs.into());
        self
    }
    /// Run this supervisor binary instead of the default (self-update tests).
    pub fn supervisor_bin(mut self, path: &Path) -> Self {
        self.supervisor_override = Some(path.to_path_buf());
        self
    }

    /// Start with only bootstrap + supervisor; the supervisor must install the
    /// first trusted application before the guardian launches anything.
    pub fn cold_install(mut self) -> Self {
        self.seed_application = false;
        self
    }

    /// The guardian's state directory for this scenario.
    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("guardian-state")
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
            &updated::bundle::Entrypoints {
                entrypoint: &entrypoint,
                // A `custom` lifecycle provider reloads in place: the same script is its `activate`
                // entrypoint, so the supervisor derives reload mode from the artifact.
                activate: (self.custom && kind == "lifecycle").then_some(entrypoint.as_str()),
                rollback: None,
            },
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
            release: staged.id,
            archive_sha256: staged.archive_sha256,
            args: signed_args,
            timeout_millis: 5000,
        })
    }

    /// Publish a signed provider artifact of `kind` (`lifecycle` / `healthcheck`) built from
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
                .args(["--entrypoint", &published_entrypoint])
                // A `custom` lifecycle deployment reloads in place: ship the same script as the
                // `activate` entrypoint so the supervisor derives reload mode from the artifact.
                .args(reload_activate_args(
                    kind,
                    self.custom,
                    &published_entrypoint,
                )),
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
        if self.lifecycle_command.is_some() || self.health_command.is_some() {
            let mut provider_set = Command::new(&self.server_bin);
            provider_set
                .arg("publish-provider-set")
                .arg("--repo")
                .arg(self.dir.join("repo"))
                .arg("--keys")
                .arg(self.dir.join("keys"))
                .args(["--id", "default"]);
            if let Some(c) = self.lifecycle_command.clone() {
                let (path, sha, signed_args) = self.publish_provider("lifecycle", &c)?;
                provider_set
                    .args(["--provider-path", &path])
                    .args(["--provider-sha256", &sha])
                    .args(["--provider-timeout-ms", "5000"]);
                for arg in &signed_args {
                    provider_set.args(["--provider-arg", arg]);
                }
            }
            if let Some(c) = self.health_command.clone() {
                let (path, sha, signed_args) = self.publish_provider("healthcheck", &c)?;
                provider_set
                    .args(["--health-provider-path", &path])
                    .args(["--health-provider-sha256", &sha])
                    .args(["--health-provider-timeout-ms", "5000"]);
                for arg in &signed_args {
                    provider_set.args(["--health-provider-arg", arg]);
                }
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
        let runtime = updated::config::ManagedRuntime {
            product: self.product.clone(),
            channel: "stable".into(),
            install_root: self.install_root.clone(),
            args: self.args.clone(),
            health_checks: self.health_checks.clone(),
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 5,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 1,
                inactive_bytes: 1024 * 1024 * 1024,
                inactive_repository_caches: 2,
            },
            timeouts: updated::config::ManagedTimeouts {
                check_interval_seconds: seconds(self.check_interval.as_ref(), 15)?,
                health_grace_seconds: seconds(self.health_grace.as_ref(), 10)?,
                health_successes: self.health_successes,
                health_interval_seconds: 1,
                retry_after_seconds: seconds(self.retry_after.as_ref(), 300)?,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: seconds(self.confirmation_window.as_ref(), 120)?,
                supervisor_check_interval_seconds: seconds(
                    self.supervisor_check_interval.as_ref(),
                    3600,
                )?,
                drain_hold_seconds: Some(0),
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
        // Every test agent now starts from the same signed enrollment artifact as a
        // production installer. Ensure a (possibly empty) `default` provider set exists even
        // when the repository is intentionally never served (the offline one-shot scenario).
        // Only when no provider was published above — otherwise this would overwrite that set.
        if self.lifecycle_command.is_none() && self.health_command.is_none() {
            crate::harness::run(
                Command::new(&self.server_bin)
                    .arg("publish-provider-set")
                    .arg("--repo")
                    .arg(self.dir.join("repo"))
                    .arg("--keys")
                    .arg(self.dir.join("keys"))
                    .args(["--id", "default"]),
            )?;
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
        let bootstrap = self.dir.join(format!(
            "bootstrap-{}.toml",
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &bootstrap,
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
        Ok(bootstrap)
    }

    fn seed_install(&self) -> R {
        let paths = updated::config::Paths {
            install_root: self.install_root.clone(),
            versions: self.install_root.join("versions"),
            staging: self.install_root.join("staging"),
            active_release: self.install_root.join("active-release"),
            download: self.install_root.join("staging/bundle.download"),
            state: self.install_root.join("state/installed.json"),
            datastore: self.install_root.join("state/tuf"),
            routing_datastore: self.install_root.join("state/routing-tuf"),
            assignment: self.install_root.join("state/repository-assignment.json"),
            journal: self.install_root.join("state/transaction.json"),
            install_journal: self.install_root.join("state/install.json"),
            rejected: self.install_root.join("state/rejected"),
            app_token: self.install_root.join("state/app-token"),
            provider_versions: self.install_root.join("providers/versions"),
            provider_staging: self.install_root.join("providers/staging"),
            provider_download: self.install_root.join("providers/staging/bundle.download"),
        };
        if matches!(
            updated::state::read_installed(&paths.state),
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
            &updated::bundle::Entrypoints::new(&entrypoint),
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
        updated::bundle::write_active(&paths.active_release, &staged.id).map_err(str_err)?;
        let lineage = updated::state::RepositoryLineage::from_metadata_url(&format!(
            "{}metadata/",
            self.repository_base_url
        ));
        updated::state::enroll(&paths.state, lineage.clone()).map_err(str_err)?;
        // Carry the same signed provider set the published assignment references, so the seeded
        // predecessor is faithful to a cold-installed node (install stages its providers). Without
        // this the first update's rollback restores a predecessor with no providers to replay.
        let mut installed =
            updated::state::InstalledState::confirmed(lineage, staged.id, staged.archive_sha256);
        if let Some(command) = self.lifecycle_command.clone() {
            installed = installed.with_lifecycle(Some(Box::new(self.stage_seed_provider(
                &paths,
                "lifecycle",
                &command,
            )?)));
        }
        if let Some(command) = self.health_command.clone() {
            installed = installed.with_healthcheck(Some(Box::new(self.stage_seed_provider(
                &paths,
                "healthcheck",
                &command,
            )?)));
        }
        updated::state::write_installed(&paths.state, &installed).map_err(str_err)
    }

    /// A guardian command: `bootstrap --state-dir <dir> --supervisor-config <cfg>
    /// --supervisor <supervisor>`. This is the whole tower — the guardian owns the app,
    /// launches the supervisor, and reflects the app's exit code.
    pub fn guardian(self) -> R<Command> {
        let state_dir = self.state_dir();
        std::fs::create_dir_all(&state_dir).map_err(str_err)?;
        let supervisor = self
            .supervisor_override
            .clone()
            .unwrap_or_else(|| self.supervisor_bin.clone());
        let ready_timeout = self.ready_timeout.clone().unwrap_or_else(|| "30".into());
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.guardian_bin);
        c.arg("--state-dir")
            .arg(&state_dir)
            .arg("--supervisor-config")
            .arg(&cfg)
            .arg("--supervisor")
            .arg(&supervisor)
            .arg("--ready-timeout")
            .arg(&ready_timeout)
            .arg("--confirm-timeout")
            .arg("1");
        if let Some(address) = &self.probe_address {
            c.arg("--probe-address").arg(address);
        }
        Ok(c)
    }

    /// A one-shot updater command (`updated-oneshot --config <written file>`). Shares
    /// the exact same config the supervisor reads.
    pub fn oneshot(self) -> R<Command> {
        let state_dir = self.state_dir();
        let cfg = self.write_config()?;
        let mut c = Command::new(&self.oneshot_bin);
        c.arg("--config").arg(cfg).arg("--state-dir").arg(state_dir);
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

pub fn republish_assignment(sup: &Sup, deployment: &str) -> R {
    let desired = std::fs::read_to_string(sup.dir.join("desired-app")).map_err(str_err)?;
    let mut desired = desired.lines();
    let app_path = desired
        .next()
        .ok_or("desired application path is missing")?;
    let app_sha = desired
        .next()
        .ok_or("desired application hash is missing")?;
    let set_path = "provider-sets/default.json";
    let set_sha = target_sha256(&sup.server_bin, &sup.dir, set_path)?;
    let runtime = sup.dir.join("assignment-runtime.json");
    let mut command = Command::new(&sup.server_bin);
    command
        .arg("publish-assignment")
        .arg("--repo")
        .arg(sup.dir.join("repo"))
        .arg("--keys")
        .arg(sup.dir.join("keys"))
        .args(["--name", "assignments/agents/agent.json"])
        .args([
            "--metadata-url",
            &format!("{}metadata/", sup.repository_base_url),
        ])
        .args([
            "--targets-url",
            &format!("{}targets/", sup.repository_base_url),
        ])
        .args(["--deployment", deployment])
        .args(["--application-path", app_path])
        .args(["--application-sha256", app_sha])
        .args(["--provider-set-path", set_path])
        .args(["--provider-set-sha256", &set_sha])
        .arg("--runtime")
        .arg(runtime);
    // The Sup builder drops this marker when ordered-install fallback is opted into; it must
    // ride the *initial* assignment (this is the doc a cold node resolves), not only later
    // republishes, or the first install pins the assigned head exactly and cannot descend.
    if sup.dir.join("ordered-install-fallback").exists() {
        command.arg("--ordered-install-fallback");
    }
    crate::harness::run(&mut command)
}
