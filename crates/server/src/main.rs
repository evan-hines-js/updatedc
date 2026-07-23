//! Development TUF publisher and static repository server (the mock CDN).
//!
//! - `init`    mint the four ed25519 role keys and an empty signed repository.
//! - `publish-app` build and publish application bundles.
//! - `install-app` seed an installer-verified application bundle.
//! - `publish-supervisor` publish supervisor bootstrap binaries.
//! - `publish-provider-set` publish an immutable exact provider collection.
//! - `publish-assignment` publish an exact desired deployment last.
//! - `serve`   serve the repository directory over HTTP for clients to refresh.
//!
//! Publishing is an offline/CI operation; a deployed client never runs it.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use updated_tuf::repo::{self, PublishTarget};

mod certs;

type R = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    let result = match cmd {
        "init" => init(rest).await,
        "publish-app" | "publish-provider-artifact" => publish(rest, true).await,
        "install-app" => install_app(rest),
        "publish-supervisor" => publish(rest, false).await,
        "publish-provider-set" => publish_provider_set(rest).await,
        "publish-assignment" => publish_assignment(rest).await,
        "export-enrollment" => export_enrollment(rest),
        "target-sha256" => target_sha256(rest).await,
        "gen-certs" => gen_certs(rest).await,
        "serve" => serve(rest).await,
        other => {
            eprintln!("unknown or missing subcommand: {other:?}");
            eprintln!(
                "usage: server <init|install-app|publish-app|publish-provider-artifact|publish-supervisor|publish-provider-set|publish-assignment|export-enrollment|target-sha256|serve> [flags]"
            );
            exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        exit(1);
    }
}

fn export_enrollment(args: &[String]) -> R {
    let repo = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let assignment = flag(args, "--assignment").ok_or("--assignment <target-path> is required")?;
    let agent_id = flag(args, "--agent-id").ok_or("--agent-id <id> is required")?;
    let routing_base_url = flag(args, "--routing-base-url")
        .ok_or("--routing-base-url <url-or-absolute-path> is required")?;
    let output = PathBuf::from(flag(args, "--output").ok_or("--output <path> is required")?);
    let metadata = repo.join("metadata");
    let root = std::fs::read_to_string(metadata.join("root.json"))?;
    let timestamp = std::fs::read_to_string(metadata.join("timestamp.json"))?;
    let timestamp_value: serde_json::Value = serde_json::from_str(&timestamp)?;
    let snapshot_version = timestamp_value
        .pointer("/signed/meta/snapshot.json/version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("timestamp omits snapshot.json version")?;
    let snapshot =
        std::fs::read_to_string(metadata.join(format!("{snapshot_version}.snapshot.json")))?;
    let snapshot_value: serde_json::Value = serde_json::from_str(&snapshot)?;
    let targets_version = snapshot_value
        .pointer("/signed/meta/targets.json/version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("snapshot omits targets.json version")?;
    let targets =
        std::fs::read_to_string(metadata.join(format!("{targets_version}.targets.json")))?;
    let targets_value: serde_json::Value = serde_json::from_str(&targets)?;
    let agent_document = repository_target_text(&repo, &targets_value, &assignment)?;
    let agent: updated::config::AgentDocument = serde_json::from_str(&agent_document)?;
    agent.validate()?;
    let managed_configuration = repository_target_text(&repo, &targets_value, &agent.config.path)?;
    let bundle = updated::enrollment::EnrollmentBundle {
        schema: 1,
        agent_id,
        routing_base_url: ensure_base_location(routing_base_url),
        assignment,
        routing_root: root,
        initial: updated::enrollment::InitialSignedConfiguration {
            timestamp,
            snapshot,
            targets,
            agent_document,
            managed_configuration,
        },
    };
    bundle.validate_shape()?;
    foundation::durable::atomic_write(
        &output,
        ".enrollment-",
        &serde_json::to_vec_pretty(&bundle)?,
    )?;
    println!("exported signed enrollment bundle to {}", output.display());
    Ok(())
}

fn repository_target_text(
    repo: &Path,
    targets: &serde_json::Value,
    logical: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let sha = targets
        .pointer(&format!(
            "/signed/targets/{}/hashes/sha256",
            logical.replace('~', "~0").replace('/', "~1")
        ))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("targets metadata omits {logical}"))?;
    Ok(std::fs::read_to_string(
        repo.join("targets").join(format!("{sha}.{logical}")),
    )?)
}

fn ensure_base_location(mut value: String) -> String {
    if !value.ends_with('/') {
        value.push('/');
    }
    value
}

async fn target_sha256(args: &[String]) -> R {
    let repo = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let name = flag(args, "--name").ok_or("--name <target-path> is required")?;
    println!("{}", repo::target_sha256(&repo, &name).await?);
    Ok(())
}

async fn publish_assignment(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let keys_dir = PathBuf::from(flag(args, "--keys").ok_or("--keys <dir> is required")?);
    let name = flag(args, "--name").ok_or("--name <target-path> is required")?;
    let metadata_url = flag(args, "--metadata-url").ok_or("--metadata-url <url> is required")?;
    let targets_url = flag(args, "--targets-url").ok_or("--targets-url <url> is required")?;
    let deployment = flag(args, "--deployment").ok_or("--deployment <id> is required")?;
    let application = target_reference(args, "application")?;
    let ordered_install_fallback = args.iter().any(|arg| arg == "--ordered-install-fallback");
    let provider_set = target_reference(args, "provider-set")?;
    // The release trust anchor belongs to the repository being assigned. Keeping it
    // adjacent to that repository eliminates a second caller-supplied root path.
    let release_root_path = repo_dir.join("metadata/root.json");
    let release_root = serde_json::from_slice(&std::fs::read(release_root_path)?)?;
    let runtime_path = flag(args, "--runtime").ok_or("--runtime <runtime.json> is required")?;
    let runtime = serde_json::from_slice(&std::fs::read(runtime_path)?)?;
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;
    let config_source = repo_dir.join(".config-build.json");
    let node_source = repo_dir.join(".node-build.json");
    let assignment = updated::config::RepositoryAssignment {
        schema: 2,
        deployment,
        metadata_url,
        targets_url,
        report_url: None,
        application,
        ordered_install_fallback,
        provider_set,
        release_root,
        runtime,
    };
    assignment.validate()?;
    let config_bytes = serde_json::to_vec(&assignment)?;
    let config_sha256 = updated::hash::sha256_bytes(&config_bytes);
    let (prefix, node_id) = name
        .rsplit_once("/agents/")
        .filter(|(prefix, node)| !prefix.is_empty() && !node.is_empty())
        .ok_or("--name must use <prefix>/agents/<agent>.json")?;
    let config_name = format!("{prefix}/configs/{config_sha256}.json");
    let node = updated::config::AgentDocument {
        schema: 1,
        config: updated::config::TargetReference {
            path: config_name.clone(),
            sha256: config_sha256,
        },
        // The dev/e2e publisher does not model an external intermediary; nodes it seeds
        // self-manage with their own probes.
        status: None,
    };
    node.validate()?;
    foundation::durable::atomic_write(&config_source, ".config-", &config_bytes)?;
    foundation::durable::atomic_write(&node_source, ".node-", &serde_json::to_vec(&node)?)?;
    let keys = repo::Keys::in_dir(&keys_dir);
    let _publish_lock = lock_publisher(&repo_dir)?;
    repo::add_release(
        &repo_dir,
        &keys,
        vec![
            PublishTarget {
                name: config_name,
                source: config_source.clone(),
                custom: Default::default(),
            },
            PublishTarget {
                name: name.clone(),
                source: node_source.clone(),
                custom: Default::default(),
            },
        ],
        expiry_days,
    )
    .await?;
    let _ = std::fs::remove_file(config_source);
    let _ = std::fs::remove_file(node_source);
    println!("published routing agent document {name} for {node_id}");
    Ok(())
}

async fn publish_provider_set(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let keys_dir = PathBuf::from(flag(args, "--keys").ok_or("--keys <dir> is required")?);
    let id = flag(args, "--id").ok_or("--id <provider-set-id> is required")?;
    // Each capability is published from its own flag prefix; a set may carry a lifecycle
    // override, a health-check override, both, or (for a provider-less set) neither.
    let override_for =
        |prefix: &str,
         arg_flag: &str,
         timeout_flag: &str,
         capability: updated::config::ProviderCapability|
         -> Result<Option<updated::config::ProviderOverride>, Box<dyn std::error::Error>> {
            if flag(args, &format!("--{prefix}-path")).is_none() {
                return Ok(None);
            }
            Ok(Some(updated::config::ProviderOverride {
                capability,
                artifact: target_reference(args, prefix)?,
                args: flags_all(args, arg_flag),
                timeout_millis: flag(args, timeout_flag)
                    .unwrap_or_else(|| "300000".into())
                    .parse()?,
            }))
        };
    let overrides = [
        override_for(
            "provider",
            "--provider-arg",
            "--provider-timeout-ms",
            updated::config::ProviderCapability::Lifecycle,
        )?,
        override_for(
            "health-provider",
            "--health-provider-arg",
            "--health-provider-timeout-ms",
            updated::config::ProviderCapability::HealthCheck,
        )?,
    ]
    .into_iter()
    .flatten()
    .collect();
    let set = updated::config::ProviderSet {
        schema: 2,
        id: id.clone(),
        overrides,
    };
    let source = repo_dir.join(".provider-set-build.json");
    foundation::durable::atomic_write(&source, ".provider-set-", &serde_json::to_vec(&set)?)?;
    let name = format!("provider-sets/{id}.json");
    let keys = repo::Keys::in_dir(&keys_dir);
    let _publish_lock = lock_publisher(&repo_dir)?;
    repo::add_release(
        &repo_dir,
        &keys,
        vec![PublishTarget {
            name: name.clone(),
            source: source.clone(),
            custom: Default::default(),
        }],
        flag_i64(args, "--expiry-days", 365)?,
    )
    .await?;
    let _ = std::fs::remove_file(source);
    println!("published provider set {name}");
    Ok(())
}

fn target_reference(
    args: &[String],
    prefix: &str,
) -> Result<updated::config::TargetReference, Box<dyn std::error::Error>> {
    let path = flag(args, &format!("--{prefix}-path"))
        .ok_or_else(|| format!("--{prefix}-path <target> is required"))?;
    let sha256 = flag(args, &format!("--{prefix}-sha256"))
        .ok_or_else(|| format!("--{prefix}-sha256 <hex> is required"))?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("--{prefix}-sha256 must be 64 hexadecimal characters").into());
    }
    Ok(updated::config::TargetReference {
        path,
        sha256: sha256.to_ascii_lowercase(),
    })
}

fn install_app(args: &[String]) -> R {
    let install_root =
        PathBuf::from(flag(args, "--install-root").ok_or("--install-root <dir> is required")?);
    let source = PathBuf::from(flag(args, "--bundle").ok_or("--bundle <dir> is required")?);
    let product = flag(args, "--product").ok_or("--product <name> is required")?;
    let version = flag(args, "--version").ok_or("--version <semver> is required")?;
    semver::Version::parse(&version).map_err(|e| format!("invalid --version: {e}"))?;
    let platform = flag(args, "--platform").ok_or("--platform <os>-<arch> is required")?;
    let entrypoint =
        flag(args, "--entrypoint").ok_or("--entrypoint <relative-path> is required")?;
    let metadata_url = flag(args, "--metadata-url")
        .ok_or("--metadata-url <trusted repository metadata base URL> is required")?;
    let state_dir = install_root.join("state");
    let staging = install_root.join("staging");
    let versions = install_root.join("versions");
    std::fs::create_dir_all(&state_dir)?;
    let archive = staging.join("installer-bundle.tar.zst");
    updated::bundle::create_bundle(
        &source,
        &archive,
        &product,
        &version,
        &platform,
        &updated::bundle::Entrypoints::new(&entrypoint),
    )?;
    // Seed the baseline through the same default provider the tower installs with, so
    // the installer and the running system agree on exactly one ingest path.
    let staged = updated::provider::BundleStore::new(versions, staging).install(
        &archive,
        &updated::bundle::ExpectedBundle {
            product: &product,
            version: &version,
            platform: &platform,
        },
    )?;
    updated::bundle::write_active(&install_root.join("active-release"), &staged.id)?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&metadata_url);
    updated::state::enroll(&state_dir.join("installed.json"), lineage.clone())?;
    updated::state::write_installed(
        &state_dir.join("installed.json"),
        &updated::state::InstalledState::confirmed(lineage, staged.id, staged.archive_sha256),
    )?;
    println!(
        "installed {product} {version} into {}",
        install_root.display()
    );
    Ok(())
}

// --- init -------------------------------------------------------------------

async fn init(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let keys_dir = PathBuf::from(flag(args, "--keys").ok_or("--keys <dir> is required")?);
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;

    let keys = repo::generate_keys(&keys_dir).await?;
    repo::init(&repo_dir, &keys, expiry_days).await?;
    println!(
        "initialized TUF repository at {} (keys in {})",
        repo_dir.display(),
        keys_dir.display()
    );
    println!(
        "pin this root on clients: {}",
        repo_dir.join("metadata/root.json").display()
    );
    Ok(())
}

// --- publish ----------------------------------------------------------------

async fn publish(args: &[String], application_bundle: bool) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let keys_dir = PathBuf::from(flag(args, "--keys").ok_or("--keys <dir> is required")?);
    let product = flag(args, "--product").ok_or("--product <name> is required")?;
    let channel = flag(args, "--channel").unwrap_or_else(|| "stable".into());
    let version = flag(args, "--version").ok_or("--version <semver> is required")?;
    semver::Version::parse(&version).map_err(|e| format!("invalid --version: {e}"))?;
    let component = if application_bundle {
        product.clone()
    } else {
        "supervisor".into()
    };
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;

    let artifact_flag = if application_bundle {
        "--bundle"
    } else {
        "--target"
    };
    let raw = flags_all(args, artifact_flag);
    if raw.is_empty() {
        return Err(format!("at least one {artifact_flag} <os>-<arch>=<path> is required").into());
    }
    let keys = repo::Keys::in_dir(&keys_dir);
    let _publish_lock = lock_publisher(&repo_dir)?;

    let mut targets = Vec::new();
    for t in &raw {
        let (platform, source) = t
            .split_once('=')
            .ok_or_else(|| format!("{artifact_flag} must be <os>-<arch>=<path>, got {t:?}"))?;
        let (os, arch) = platform
            .split_once('-')
            .ok_or_else(|| format!("platform must be <os>-<arch>, got {platform:?}"))?;
        let path = if application_bundle {
            let archive = repo_dir
                .join(".bundle-build")
                .join(format!("{product}-{version}-{platform}.tar.zst"));
            let input = Path::new(source);
            let prepared;
            let input = if input.is_file() {
                prepared = repo_dir
                    .join(".bundle-build")
                    .join(format!("tree-{product}-{version}-{platform}"));
                if prepared.exists() {
                    std::fs::remove_dir_all(&prepared)?;
                }
                let entrypoint =
                    flag(args, "--entrypoint").ok_or("--entrypoint <relative-path> is required")?;
                let destination = prepared.join(&entrypoint);
                std::fs::create_dir_all(destination.parent().ok_or("entrypoint has no parent")?)?;
                std::fs::create_dir_all(prepared.join("config"))?;
                std::fs::copy(input, destination)?;
                std::fs::write(
                    prepared.join("config/release.toml"),
                    format!("version = {version:?}\n"),
                )?;
                prepared.as_path()
            } else {
                input
            };
            let entrypoint =
                flag(args, "--entrypoint").ok_or("--entrypoint <relative-path> is required")?;
            let activate = flag(args, "--activate");
            let rollback = flag(args, "--rollback");
            updated::bundle::create_bundle(
                input,
                &archive,
                &product,
                &version,
                platform,
                &updated::bundle::Entrypoints {
                    entrypoint: &entrypoint,
                    activate: activate.as_deref(),
                    rollback: rollback.as_deref(),
                },
            )?;
            // Test-only: deliberately damage the just-built archive. It is corrupted *before*
            // `add_release` hashes it, so the published target is signed for its own broken bytes —
            // it passes the client's download sha check and fails only at extract/validate. This is
            // the malformed-but-signed bundle an honest publisher can never emit, used to exercise
            // the client's ingest-rejection + ordered-fallback descent. Never used by real releases.
            if let Some(kind) = flag(args, "--corrupt") {
                corrupt_archive(&archive, &kind, &version)?;
            }
            archive
        } else {
            PathBuf::from(source)
        };
        targets.push(PublishTarget::application(
            &product, &channel, &version, os, arch, &component, path,
        ));
    }

    for t in &targets {
        println!("  {}", t.name);
    }

    // `publish` is commonly invoked as many short-lived CLI processes (the
    // smoke fuzzer does exactly that), so an in-process mutex is insufficient.
    // Keep the development server's single-writer policy here rather than in
    // the reusable TUF authoring library.
    repo::add_release(&repo_dir, &keys, targets, expiry_days).await?;
    println!("published {product} {version} on channel {channel}");
    Ok(())
}

/// Test-only: damage a built bundle archive in a chosen way, keeping it signed for its (now
/// corrupt) bytes so it passes the download sha check and fails only at extract/validate — the
/// client's defense against a malformed-but-signed bundle. Distinct per version, so a descent
/// rejects independent hashes.
fn corrupt_archive(archive: &Path, kind: &str, version: &str) -> R {
    match kind {
        // Not a valid zstd stream at all: decompression fails outright.
        "garbage" => std::fs::write(archive, format!("corrupt-archive-{version}\n").repeat(64))?,
        // A truncated tar.zst: decompression / untar hits an unexpected EOF partway through.
        "truncate" => {
            let bytes = std::fs::read(archive)?;
            std::fs::write(archive, &bytes[..bytes.len() / 2])?;
        }
        other => return Err(format!("unknown --corrupt kind {other:?}").into()),
    }
    Ok(())
}

fn lock_publisher(repo_dir: &Path) -> std::io::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(repo_dir.join(".publish.lock"))?;
    lock.lock()?;
    Ok(lock)
}

// --- serve ------------------------------------------------------------------

/// Mint the fleet CA + gateway server cert + agent client cert into `--dir`. Each `--san`
/// is a name the gateway is reached by (repeatable). The local counterpart of cert-manager.
async fn gen_certs(args: &[String]) -> R {
    let dir = PathBuf::from(flag(args, "--dir").ok_or("--dir <dir> is required")?);
    let sans: Vec<String> = args
        .windows(2)
        .filter(|pair| pair[0] == "--san")
        .map(|pair| pair[1].clone())
        .collect();
    if sans.is_empty() {
        return Err("at least one --san <name> is required for the server certificate".into());
    }
    certs::generate(&dir, &sans).await?;
    println!(
        "minted fleet CA + server + client certificates in {}",
        dir.display()
    );
    Ok(())
}

async fn serve(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let addr = flag(args, "--addr").unwrap_or_else(|| "127.0.0.1:8080".into());
    let root = tokio::fs::canonicalize(&repo_dir).await?;

    // mTLS is mandatory, exactly like the gateway: the mock CDN admits a connection only if the
    // client presents a certificate the fleet CA signed. It terminates TLS here and hands the
    // decrypted stream to the same stream-generic handler.
    let cert = PathBuf::from(flag(args, "--cert").ok_or("--cert <server.crt> is required")?);
    let key = PathBuf::from(flag(args, "--key").ok_or("--key <server.key> is required")?);
    let ca = PathBuf::from(flag(args, "--ca").ok_or("--ca <ca.crt> is required")?);
    let acceptor =
        tokio_rustls::TlsAcceptor::from(Arc::new(updated::tls::server_config(&cert, &key, &ca)?));

    let listener = TcpListener::bind(&addr).await?;
    let connections = Arc::new(Semaphore::new(128));
    println!("serving {} on https://{addr} (mTLS)", root.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = connections.clone().acquire_owned().await?;
        let root = root.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // A client that fails the mTLS handshake is dropped without ever reaching the repo.
            if let Ok(stream) = acceptor.accept(stream).await {
                let _ = serve_conn(stream, &root).await;
            }
        });
    }
}

async fn serve_conn<S>(mut stream: S, root: &Path) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read request headers (bounded).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    timeout(Duration::from_secs(10), async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request header timeout"))??;
    if buf.len() > 16 * 1024 {
        respond_status(&mut stream, 431, b"request headers too large").await;
        return Ok(());
    }
    if !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        respond_status(&mut stream, 400, b"incomplete request headers").await;
        return Ok(());
    }
    let Ok(head) = std::str::from_utf8(&buf) else {
        respond_status(&mut stream, 400, b"invalid request headers").await;
        return Ok(());
    };
    let Some(request_line) = head.lines().next() else {
        respond_status(&mut stream, 400, b"missing request line").await;
        return Ok(());
    };
    let mut request = request_line.split_whitespace();
    let (Some(method), Some(path), Some(version), None) = (
        request.next(),
        request.next(),
        request.next(),
        request.next(),
    ) else {
        respond_status(&mut stream, 400, b"malformed request line").await;
        return Ok(());
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        respond_status(&mut stream, 400, b"unsupported HTTP version").await;
        return Ok(());
    }
    // As a "bring your own control plane" data plane, the server also accepts node
    // rollout telemetry — the same generic contract the k8s gateway implements — writing
    // each report beside the repository it serves.
    if method == "PUT" {
        return serve_telemetry_put(&mut stream, root, path, head, &buf).await;
    }
    if method != "GET" {
        respond_status(&mut stream, 405, b"method not allowed").await;
        return Ok(());
    }
    // A `Range: bytes=N-` header means tough is resuming a download.
    let range = head.lines().skip(1).find_map(|l| {
        let l = l.to_ascii_lowercase();
        l.strip_prefix("range:").map(|v| v.trim().to_owned())
    });
    let range_start = match range.as_deref() {
        None => None,
        Some(value) => match value
            .strip_prefix("bytes=")
            .and_then(|value| value.strip_suffix('-'))
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(start) => Some(start),
            None => {
                respond_status(&mut stream, 400, b"malformed range").await;
                return Ok(());
            }
        },
    };

    match open_repository_file(root, path) {
        Some(file) => respond_file(&mut stream, tokio::fs::File::from_std(file), range_start).await,
        None => respond_status(&mut stream, 404, b"not found").await,
    }
    Ok(())
}

/// Accept a node rollout report and persist it beside the repository at
/// `<root>/telemetry/<node>.json`. Mirrors the k8s gateway's telemetry contract: the
/// body must be a well-formed [`updated::telemetry::NodeReport`] naming the same node as
/// the path, so a malformed or misattributed report is rejected rather than stored.
async fn serve_telemetry_put<S>(
    stream: &mut S,
    root: &Path,
    path: &str,
    head: &str,
    buf: &[u8],
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(node) = updated::telemetry::node_from_path(path) else {
        respond_status(stream, 404, b"not found").await;
        return Ok(());
    };
    let content_length = head.lines().skip(1).find_map(|line| {
        let line = line.to_ascii_lowercase();
        line.strip_prefix("content-length:")
            .and_then(|value| value.trim().parse::<usize>().ok())
    });
    let Some(content_length) = content_length else {
        respond_status(stream, 411, b"length required").await;
        return Ok(());
    };
    if content_length > 64 * 1024 {
        respond_status(stream, 413, b"payload too large").await;
        return Ok(());
    }
    let start = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(buf.len());
    let mut body = buf.get(start..).unwrap_or_default().to_vec();
    body.truncate(content_length);
    let mut chunk = [0u8; 1024];
    while body.len() < content_length {
        let read = timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "body timeout"))??;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() < content_length {
        respond_status(stream, 400, b"short body").await;
        return Ok(());
    }
    body.truncate(content_length);
    let Ok(report) = serde_json::from_slice::<updated::telemetry::NodeReport>(&body) else {
        respond_status(stream, 400, b"malformed report").await;
        return Ok(());
    };
    if report.node != node {
        respond_status(stream, 400, b"report node mismatch").await;
        return Ok(());
    }
    let dest = root.join(updated::telemetry::report_object_key(node));
    if let Some(parent) = dest.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            respond_status(stream, 500, error.to_string().as_bytes()).await;
            return Ok(());
        }
    }
    match foundation::durable::atomic_write(&dest, ".telemetry-", &body) {
        Ok(()) => respond_status(stream, 200, b"ok").await,
        Err(error) => respond_status(stream, 500, error.to_string().as_bytes()).await,
    }
    Ok(())
}

/// Map a request path to a file inside `root`, rejecting traversal. Slashes are
/// allowed (TUF target paths are nested); `..` components and absolute escapes
/// are not.
fn open_repository_file(root: &Path, path: &str) -> Option<std::fs::File> {
    let path = path.split('?').next().unwrap_or(path);
    let mut out = root.to_path_buf();
    let mut parts = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".");
    let namespace = parts.next()?;
    if !matches!(namespace, "metadata" | "targets") {
        return None;
    }
    out.push(namespace);
    for part in parts {
        if part == ".." || part.contains('\\') || part.starts_with('.') {
            return None;
        }
        out.push(part);
    }
    // Open before validating and compare stable file identities afterward. If an attacker
    // swaps any ancestor or symlink during resolution, the opened handle and validated
    // canonical path refer to different files and the request fails closed.
    let file = std::fs::File::open(&out).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let opened = same_file::Handle::from_file(file.try_clone().ok()?).ok()?;
    let canonical = std::fs::canonicalize(&out).ok()?;
    if !canonical.starts_with(root) || same_file::Handle::from_path(&canonical).ok()? != opened {
        return None;
    }
    Some(file)
}

async fn respond_file<S>(stream: &mut S, mut file: tokio::fs::File, range_start: Option<u64>)
where
    S: AsyncWrite + Unpin,
{
    // The canonical repository opener admits regular files only. Metadata is read from
    // the already-validated handle so the declared response length describes these bytes.
    let Ok(metadata) = file.metadata().await else {
        respond_status(stream, 404, b"not found").await;
        return;
    };
    let length = metadata.len();
    if range_start.is_some_and(|start| start >= length) {
        let hdr = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{length}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = write_with_timeout(stream, hdr.as_bytes()).await;
        return;
    }
    let start = range_start;
    let (header, offset, count) = match start {
        Some(start) => {
            let remaining = length - start;
            let hdr = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n\
                 Content-Range: bytes {start}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                length.saturating_sub(1),
                length,
                remaining
            );
            (hdr, start, remaining)
        }
        _ => {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                length
            );
            (hdr, 0, length)
        }
    };
    if file.seek(std::io::SeekFrom::Start(offset)).await.is_err()
        || write_with_timeout(stream, header.as_bytes()).await.is_err()
    {
        return;
    }
    // Hold the body to exactly the length just declared. The size is a stat taken before
    // the first read, and the dev publisher rewrites metadata in place under live readers
    // (tough's editor truncates the same inode rather than renaming), so a file that grows
    // or shrinks mid-stream would otherwise desync the response from its own header.
    let mut chunk = [0u8; 64 * 1024];
    let mut remaining = count;
    while remaining > 0 {
        let want = remaining.min(chunk.len() as u64) as usize;
        let Ok(n) = file.read(&mut chunk[..want]).await else {
            return;
        };
        if n == 0 {
            // Short of the declared length: drop the connection rather than complete a
            // truncated body as though it were whole.
            return;
        }
        if write_with_timeout(stream, &chunk[..n]).await.is_err() {
            return;
        }
        remaining -= n as u64;
    }
    let _ = stream.flush().await;
}

async fn write_with_timeout<S>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(30), stream.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response write timeout"))?
}

async fn respond_status<S>(stream: &mut S, code: u16, body: &[u8])
where
    S: AsyncWrite + Unpin,
{
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let hdr = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(hdr.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
}

// --- flags ------------------------------------------------------------------

fn flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn flag_i64(args: &[String], name: &str, default: i64) -> Result<i64, String> {
    match flag(args, name) {
        Some(value) => value
            .parse()
            .map_err(|e| format!("invalid {name} value {value:?}: {e}")),
        None => Ok(default),
    }
}

fn flags_all(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        } else if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            out.push(v.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_seed_uses_the_canonical_bundle_layout() {
        let root = std::env::temp_dir().join(format!("server-install-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let source = root.join("source");
        let install = root.join("install");
        std::fs::create_dir_all(source.join("bin")).unwrap();
        std::fs::create_dir_all(source.join("config")).unwrap();
        std::fs::write(source.join("bin/app"), b"fixture").unwrap();
        std::fs::write(source.join("config/release.toml"), b"version = \"1.0.0\"\n").unwrap();
        let args = vec![
            "--install-root".into(),
            install.display().to_string(),
            "--bundle".into(),
            source.display().to_string(),
            "--product".into(),
            "app".into(),
            "--version".into(),
            "1.0.0".into(),
            "--platform".into(),
            "macos-aarch64".into(),
            "--entrypoint".into(),
            "bin/app".into(),
            "--metadata-url".into(),
            "https://repo/metadata/".into(),
        ];
        install_app(&args).unwrap();
        let state = match updated::state::read_installed(&install.join("state/installed.json")) {
            updated::state::Installed::Present(state) => state,
            _ => panic!("installer did not write strict installed state"),
        };
        assert_eq!(
            updated::bundle::read_active(&install.join("active-release")).unwrap(),
            Some(state.release.clone())
        );
        updated::provider::BundleStore::new(install.join("versions"), install.join("staging"))
            .resolve(&state.release)
            .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolve_allows_nested_target_paths() {
        let root = std::env::temp_dir().join(format!("server-resolve-{}", std::process::id()));
        std::fs::create_dir_all(root.join("targets/products")).unwrap();
        std::fs::create_dir_all(root.join("metadata")).unwrap();
        std::fs::write(root.join("targets/products/app"), b"target").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        assert!(open_repository_file(&root, "/targets/products/app").is_some());
        assert!(open_repository_file(&root, "/metadata").is_none());
    }

    #[test]
    fn resolve_rejects_traversal() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(open_repository_file(&root, "/../etc/passwd").is_none());
        assert!(open_repository_file(&root, "/a/../../etc").is_none());
        assert!(open_repository_file(&root, "/.publish.lock").is_none());
        assert!(open_repository_file(&root, "/keys/root.pk8").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn repository_open_rejects_symlinks_that_escape_the_root() {
        let root = serve_root("escaping-symlink");
        let outside = root.parent().unwrap().join("server-outside-target");
        std::fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("targets/escape")).unwrap();
        assert!(open_repository_file(&root, "/targets/escape").is_none());
        std::fs::remove_file(outside).unwrap();
    }

    /// Serve one request through an in-memory transport so protocol unit tests do not
    /// require permission to bind loopback sockets.
    async fn get(root: &Path, request: &str) -> String {
        let (mut client, server) = tokio::io::duplex(32 * 1024);
        let root = root.to_path_buf();
        tokio::spawn(async move {
            let _ = serve_conn(server, &root).await;
        });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn serve_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("server-serve-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("targets")).unwrap();
        std::fs::create_dir_all(root.join("metadata")).unwrap();
        std::fs::write(root.join("targets/app"), b"0123456789").unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    #[tokio::test]
    async fn a_directory_is_not_a_body() {
        // `File::open` on a directory succeeds on Unix and stats non-zero, which would
        // otherwise answer 200 with a Content-Length and then zero bytes.
        let root = serve_root("dir");
        let response = get(&root, "GET /metadata HTTP/1.1\r\n\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "a directory must 404, got: {response:?}"
        );
    }

    #[tokio::test]
    async fn the_body_matches_the_declared_content_length() {
        let root = serve_root("exact");
        let response = get(&root, "GET /targets/app HTTP/1.1\r\n\r\n").await;
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            declared,
            body.len(),
            "declared length must equal body bytes"
        );
        assert_eq!(body, "0123456789");
    }

    #[tokio::test]
    async fn a_resume_serves_exactly_the_remaining_bytes() {
        let root = serve_root("resume");
        let response = get(
            &root,
            "GET /targets/app HTTP/1.1\r\nRange: bytes=4-\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 206"), "got: {response:?}");
        assert!(response.contains("Content-Length: 6"), "got: {response:?}");
        assert!(response.ends_with("456789"), "got: {response:?}");
    }

    #[tokio::test]
    async fn unsupported_methods_are_rejected() {
        let root = serve_root("method");
        let response = get(&root, "POST /targets/app HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405"), "got: {response:?}");
    }

    #[tokio::test]
    async fn malformed_ranges_are_rejected() {
        let root = serve_root("bad-range");
        let response = get(
            &root,
            "GET /targets/app HTTP/1.1\r\nRange: bytes=wat\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "got: {response:?}");
    }

    #[tokio::test]
    async fn a_range_at_eof_is_unsatisfiable() {
        let root = serve_root("eof-range");
        let response = get(
            &root,
            "GET /targets/app HTTP/1.1\r\nRange: bytes=10-\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 416"), "got: {response:?}");
        assert!(
            response.contains("Content-Range: bytes */10"),
            "got: {response:?}"
        );
    }

    #[tokio::test]
    async fn oversized_headers_are_rejected() {
        let root = serve_root("large-header");
        let request = format!(
            "GET /targets/app HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
            "x".repeat(16 * 1024)
        );
        let response = get(&root, &request).await;
        assert!(response.starts_with("HTTP/1.1 431"), "got: {response:?}");
    }

    #[test]
    fn flags_all_collects_repeats() {
        let args = vec![
            "--target".into(),
            "linux-x86_64=./a".into(),
            "--target=macos-aarch64=./b".into(),
        ];
        assert_eq!(
            flags_all(&args, "--target"),
            vec![
                "linux-x86_64=./a".to_string(),
                "macos-aarch64=./b".to_string()
            ]
        );
    }

    #[test]
    fn invalid_integer_flag_is_rejected_instead_of_defaulted() {
        let args = vec!["--expiry-days".into(), "forever".into()];
        assert!(flag_i64(&args, "--expiry-days", 365).is_err());
        assert_eq!(flag_i64(&[], "--expiry-days", 365).unwrap(), 365);
    }

    #[test]
    fn publisher_lock_excludes_other_publishers() {
        let dir = std::env::temp_dir().join(format!(
            "updated-server-lock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let first = lock_publisher(&dir).unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(".publish.lock"))
            .unwrap();
        assert!(matches!(
            second.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));

        drop(first);
        second.try_lock().unwrap();
        drop(second);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
