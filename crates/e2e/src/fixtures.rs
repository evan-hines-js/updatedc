//! Shared test fixtures: the `Sup` supervisor/guardian config builder and version-path helpers,
//! used by the e2e scenario runner and the standalone kill fuzzer alike.

use crate::harness::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn app_v(ctx: &Ctx, v: &str) -> std::path::PathBuf {
    ctx.work.join(format!("build/app-{v}{}", ctx.exe))
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
    dir: PathBuf,
    product: String,
    pub install_root: PathBuf,
    seed_binary: PathBuf,
    args: Vec<String>,
    check_interval: Option<String>,
    health_grace: Option<String>,
    health_successes: u32,
    confirmation_window: Option<String>,
    retry_after: Option<String>,
    /// The signed lifecycle reconciler every fixture runs. Not optional: `new` always installs
    /// the default `accept-managed` fixture, and a scenario only ever swaps in its own.
    lifecycle_command: Vec<String>,
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
    secrets: Vec<updated_contracts::assignment::SecretReference>,
}
impl Sup {
    /// The tower managing `command` (the app binary + args) against the repo under
    /// `dir` served at `srv`, for `product`.
    pub fn new(ctx: &Ctx, dir: &Path, srv: &str, product: &str, command: Vec<String>) -> Self {
        let seed_binary = PathBuf::from(command.first().expect("app command requires binary"));
        let lifecycle_command = vec![
            std::env::current_exe()
                .expect("the e2e lifecycle fixture must have a current executable")
                .display()
                .to_string(),
            "--lifecycle-fixture".into(),
            dir.join("default-lifecycle-state").display().to_string(),
            "accept-managed".into(),
        ];
        Sup {
            repository_base_url: format!("https://{srv}/"),
            supervisor_bin: ctx.supervisor.clone(),
            server_bin: ctx.server.clone(),
            platform: ctx.platkey.clone(),
            exe: ctx.exe,
            guardian_bin: ctx.bootstrap.clone(),
            dir: dir.to_path_buf(),
            product: product.into(),
            install_root: dir.join("install"),
            seed_binary,
            args: command.into_iter().skip(1).collect(),
            check_interval: None,
            health_grace: None,
            health_successes: 1,
            confirmation_window: None,
            retry_after: None,
            lifecycle_command,
            supervisor_check_interval: None,
            ready_timeout: None,
            probe_address: None,
            seed_application: true,
            supervisor_override: None,
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
    /// Install the cross-platform Rust lifecycle fixture. It implements the whole lifecycle
    /// protocol and performs one HTTP observation for `verify` and `periodic`.
    pub fn readiness_health(self, svc: &str) -> Self {
        let executable = std::env::current_exe()
            .expect("the e2e lifecycle fixture must have a current executable");
        let state_dir = self.dir.join("http-lifecycle-state").display().to_string();
        self.lifecycle(vec![
            executable.display().to_string(),
            "--lifecycle-fixture".into(),
            state_dir,
            format!("http-health=http://{svc}/healthz"),
        ])
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
    pub fn lifecycle(mut self, command: Vec<String>) -> Self {
        self.lifecycle_command = command;
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
                self.publish_provider("lifecycle", &self.lifecycle_command.clone())?;
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
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: self.product.clone(),
            channel: "stable".into(),
            install_root: self.install_root.clone(),
            args: self.args.clone(),
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
                inactive_supervisors: 1,
                inactive_bytes: 1024 * 1024 * 1024,
                inactive_repository_caches: 2,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
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
        // The layout production resolves, not a copy of it: a scenario that plants or reads a
        // file through these paths must exercise the same locations the agent under test uses.
        let paths = updated::config::Paths::resolve(&self.install_root, &self.state_dir());
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
        let command = self.lifecycle_command.clone();
        let installed = updated::state::InstalledState::confirmed(
            lineage,
            staged.id,
            staged.archive_sha256,
            Box::new(self.stage_seed_provider(&paths, "lifecycle", &command)?),
        );
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
/// Both the harness's initial publish and a `Sup` republish go through it, so a change to how an
/// assignment is published (a new required flag, a changed marker) lands in exactly one place and
/// the two entry points can never drift. The metadata/targets URLs are the only per-caller inputs
/// (the harness derives them from a listen address; a `Sup` from its repository base).
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
    // The Sup builder drops this marker when ordered-install fallback is opted into; it must
    // ride the *initial* assignment (this is the doc a cold node resolves), not only later
    // republishes, or the first install pins the assigned head exactly and cannot descend.
    if dir.join("ordered-install-fallback").exists() {
        command.arg("--ordered-install-fallback");
    }
    crate::harness::run(&mut command)
}

pub fn republish_assignment(sup: &Sup, deployment: &str) -> R {
    publish_assignment(
        &sup.server_bin,
        &sup.dir,
        &format!("{}metadata/", sup.repository_base_url),
        &format!("{}targets/", sup.repository_base_url),
        deployment,
    )
}
