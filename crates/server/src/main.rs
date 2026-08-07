//! Development TUF publisher and static repository server (the mock CDN).
//!
//! - `init`    mint the five ed25519 role keys and an empty signed repository.
//! - `publish-app` build and publish application bundles.
//! - `publish-provider-artifact` alias of `publish-app` for provider binaries.
//! - `publish-supervisor` publish supervisor bootstrap binaries.
//! - `publish-provider-set` publish an immutable exact provider collection.
//! - `publish-assignment` publish an exact desired deployment last.
//! - `export-enrollment` write the enrollment bundle a node boots from.
//! - `target-sha256` print the content address of a published target.
//! - `gen-certs` mint the development mTLS certificate hierarchy.
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
                "usage: server <init|publish-app|publish-provider-artifact|publish-supervisor|publish-provider-set|publish-assignment|export-enrollment|target-sha256|gen-certs|serve> [flags]"
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
    let agent: updated_contracts::artifact::AgentDocument = serde_json::from_str(&agent_document)?;
    agent.validate()?;
    let managed_configuration = repository_target_text(&repo, &targets_value, &agent.config.path)?;
    let bundle = updated_contracts::enrollment::EnrollmentBundle {
        schema: 1,
        agent_id,
        routing_base_url: ensure_base_location(routing_base_url),
        assignment,
        routing_root: root,
        initial: updated_contracts::enrollment::InitialSignedConfiguration {
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
    // Where the node PUTs its signed running-state report. Optional, because a repository that
    // nothing reads reports from does not need one — but without it `report_running_state` returns
    // immediately, so every consumer of this repository (a healthproxy above all) sees a fleet that
    // never speaks. `RepositoryAssignment::validate` below holds it to the same shape the control
    // plane's own assignments carry.
    let report_url = flag(args, "--report-url");
    let config_source = repo_dir.join(".config-build.json");
    let node_source = repo_dir.join(".node-build.json");
    let assignment = updated_contracts::assignment::RepositoryAssignment {
        schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
        deployment,
        metadata_url,
        targets_url,
        report_url,
        application,
        ordered_install_fallback,
        provider_set,
        release_root,
        runtime,
    };
    assignment.validate()?;
    let config_bytes = serde_json::to_vec(&assignment)?;
    let config_sha256 = updated::hash::sha256_bytes(&config_bytes);
    let (prefix, node_id) = updated_contracts::telemetry::split_assignment_path(&name)
        .ok_or("--name must use <prefix>/agents/<agent>.json")?;
    let config_name = updated_contracts::telemetry::config_object_key(prefix, &config_sha256);
    let node = updated_contracts::artifact::AgentDocument {
        schema: 1,
        config: updated_contracts::artifact::TargetReference {
            path: config_name.clone(),
            sha256: config_sha256,
        },
    };
    node.validate()?;
    let keys = repo::Keys::in_dir(&keys_dir);
    // Staging comes AFTER the lock, exactly as in `publish`: these are fixed names in the shared
    // repository directory, and `add_release` reads them back to hash and sign. Staging outside the
    // lock lets a second publisher overwrite them in that gap, so each process signs the other's
    // bytes — an AgentDocument declaring `config.sha256` of one configuration over a target holding
    // another's — and the cleanup below deletes a concurrent publisher's staging file.
    let _publish_lock = lock_publisher(&repo_dir)?;
    foundation::durable::atomic_write(&config_source, ".config-", &config_bytes)?;
    foundation::durable::atomic_write(&node_source, ".node-", &serde_json::to_vec(&node)?)?;
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
    let reconciler = updated_contracts::artifact::Reconciler {
        artifact: target_reference(args, "provider")?,
        args: flags_all(args, "--provider-arg"),
        timeout_millis: flag(args, "--provider-timeout-ms")
            .unwrap_or_else(|| "300000".into())
            .parse()?,
    };
    let set = updated_contracts::artifact::ProviderSet {
        schema: updated_contracts::artifact::ProviderSet::SCHEMA,
        id: id.clone(),
        reconciler,
    };
    // Validate before anything is signed: a published target is immutable and keyed by id, so a
    // set that every node's `set.validate()` rejects at selection time could only be repaired by
    // republishing under a *new* id. Same gate, same reason, as the production publisher.
    set.validate().map_err(|error| {
        format!("refusing to publish provider set {id:?}: {error} (nothing was signed or uploaded)")
    })?;
    let source = repo_dir.join(".provider-set-build.json");
    let name = format!("provider-sets/{id}.json");
    let keys = repo::Keys::in_dir(&keys_dir);
    // Under the lock before the staging write, for the same reason as `publish_assignment`: the
    // staging name is fixed and shared, and `add_release` signs whatever bytes it finds there.
    let _publish_lock = lock_publisher(&repo_dir)?;
    repo::verify_provider_set_reconciler(&repo_dir, &set).await?;
    foundation::durable::atomic_write(&source, ".provider-set-", &serde_json::to_vec(&set)?)?;
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
) -> Result<updated_contracts::artifact::TargetReference, Box<dyn std::error::Error>> {
    let path = flag(args, &format!("--{prefix}-path"))
        .ok_or_else(|| format!("--{prefix}-path <target> is required"))?;
    let sha256 = flag(args, &format!("--{prefix}-sha256"))
        .ok_or_else(|| format!("--{prefix}-sha256 <hex> is required"))?;
    if !updated_contracts::is_sha256_hex(&sha256) {
        return Err(format!("--{prefix}-sha256 must be 64 hexadecimal characters").into());
    }
    Ok(updated_contracts::artifact::TargetReference {
        path,
        sha256: sha256.to_ascii_lowercase(),
    })
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
            let wrap_dir = repo_dir
                .join(".bundle-build")
                .join(format!("tree-{product}-{version}-{platform}"));
            let entrypoint =
                flag(args, "--entrypoint").ok_or("--entrypoint <relative-path> is required")?;
            updated::bundle::create_bundle_from_source(
                Path::new(source),
                &archive,
                &wrap_dir,
                &product,
                &version,
                platform,
                &entrypoint,
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

/// Take the repository's single-writer lock, held for the rest of the publish.
///
/// Every publish subcommand is commonly invoked as many short-lived CLI processes (the smoke fuzzer
/// does exactly that), so an in-process mutex is insufficient. It is taken before *any* mutable
/// state in the repository directory is touched — the build/staging files a publish signs from as
/// much as the metadata `add_release` rewrites — because those are fixed names in a shared
/// directory: staging outside the lock lets two publishers sign each other's bytes. Keep the
/// development server's single-writer policy here rather than in the reusable TUF authoring library.
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
    // Through the same repeatable-flag reader as `--target`/`--bundle`, so `--san name` and
    // `--san=name` both work. Recognizing only the space-separated form silently dropped the
    // equals form: certificates minted without a name the gateway is actually reached by, and no
    // error until every agent's handshake fails.
    let sans = flags_all(args, "--san");
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
        // An accept error is recoverable and must never take the server down: ECONNABORTED (a peer
        // that reset between SYN and accept) and EMFILE/ENFILE (the fd ceiling, reachable at 128
        // concurrent connections each also holding an open repository file) would otherwise exit
        // the process and cut every agent off from its metadata and targets.
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                eprintln!("server: accept failed ({error}); continuing");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let permit = connections.clone().acquire_owned().await?;
        let root = root.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // The handshake is bounded like every other phase. Without it a client that opens a
            // connection and sends nothing holds its permit forever; 128 of those exhaust the
            // semaphore, the accept loop blocks on `acquire_owned`, and the server stops serving
            // entirely — no error, no recovery.
            // A client that fails the mTLS handshake is dropped without ever reaching the repo.
            if let Ok(Ok(stream)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                let _ = serve_conn(stream, &root).await;
            }
        });
    }
}

/// How long a client has to complete the TLS handshake while holding a connection permit.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a handshaken client has to finish its one request while holding a connection permit.
///
/// Every individual phase is already bounded — the header read, the telemetry body read, each
/// `write_all` — but per-operation bounds do not bound the connection: a client that drains one
/// 64 KiB chunk every ~25s keeps every write inside `write_with_timeout` forever and holds its
/// permit indefinitely. 128 such connections exhaust the semaphore, the accept loop blocks on
/// `acquire_owned`, and the server stops serving entirely — the same wedge `HANDSHAKE_TIMEOUT`
/// exists to prevent, just moved past the handshake. Generous enough that an honest agent pulling
/// the largest target off this loopback CDN never trips it.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// Serve the connection's one request under an overall deadline, so a permit's lifetime is bounded
/// by `HANDSHAKE_TIMEOUT + CONNECTION_TIMEOUT` no matter how the peer behaves.
async fn serve_conn<S>(stream: S, root: &Path) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(CONNECTION_TIMEOUT, serve_request(stream, root))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection deadline"))?
}

async fn serve_request<S>(mut stream: S, root: &Path) -> std::io::Result<()>
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
    if path == "/v1/node/secrets" {
        let bundle = root
            .parent()
            .map(|parent| parent.join("secret-bundle.json"));
        match bundle.and_then(|path| std::fs::read(path).ok()) {
            Some(body) => respond_secret_bundle(&mut stream, &body).await,
            None => respond_status(&mut stream, 503, b"secret bundle unavailable").await,
        }
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

async fn respond_secret_bundle<S>(stream: &mut S, body: &[u8])
where
    S: AsyncWrite + Unpin,
{
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

/// Accept a node rollout report and persist it beside the repository at
/// `<root>/telemetry/<node>.json`. Mirrors the k8s gateway's telemetry contract: the
/// body must be a well-formed [`updated_contracts::telemetry::NodeReport`] naming the same node as
/// the path, so a malformed or misattributed report is rejected rather than stored.
///
/// Unlike the production k8s gateway (`updatec::gateway::telemetry_put`), this dev/mock CDN does
/// NOT authorize the report against the caller's mTLS leaf identity: `gen_certs` mints a single
/// shared fleet client certificate, so there is no per-node identity to bind the path node against
/// — the check is not expressible here. The report signature is still what makes a report
/// trustworthy end-to-end (the control plane and health proxy verify it against the node's pinned
/// key), so this omission only lets a shared-cert peer overwrite another node's report with bytes
/// that then fail verification and fail closed. Do not copy this handler as the production contract.
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
    let Some(node) = updated_contracts::telemetry::node_from_path(path) else {
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
    // The same envelope bound every other hop enforces, so the dev CDN accepts exactly the reports
    // the production gateway does — and exactly the ones a node may sign.
    if content_length > updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES {
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
    // A report travels as a signed DSSE envelope, exactly as the k8s gateway stores it — that is
    // what a consumer verifies against the node's pinned key. Parsing the body as a bare report
    // rejected every genuine agent write with "malformed report" and left this handler storing
    // nothing at all.
    let Ok(envelope) = serde_json::from_slice::<updated_contracts::telemetry::Envelope>(&body)
    else {
        respond_status(stream, 400, b"malformed report envelope").await;
        return Ok(());
    };
    if envelope.payload_type != updated_contracts::telemetry::REPORT_PAYLOAD_TYPE
        || envelope.signatures.len() > updated_contracts::telemetry::Envelope::MAX_SIGNATURES
    {
        respond_status(stream, 400, b"malformed report envelope").await;
        return Ok(());
    }
    let Some(report) = updated_contracts::telemetry::report_payload_unverified(&envelope) else {
        respond_status(stream, 400, b"malformed report").await;
        return Ok(());
    };
    if report.node != node || !report.is_wellformed() {
        respond_status(stream, 400, b"report node mismatch").await;
        return Ok(());
    }
    let dest = root.join(updated_contracts::telemetry::report_object_key(node));
    if let Some(parent) = dest.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            respond_status(stream, 500, error.to_string().as_bytes()).await;
            return Ok(());
        }
    }
    // `atomic_write` fsyncs the file and its directory — hundreds of milliseconds on a busy disk,
    // on a runtime worker that is also serving every other agent's metadata fetch. Hand it to the
    // blocking pool.
    let written = tokio::task::spawn_blocking(move || {
        foundation::durable::atomic_write(&dest, ".telemetry-", &body)
    })
    .await
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    match written {
        Ok(()) => respond_status(stream, 200, b"ok").await,
        Err(error) => respond_status(stream, 500, error.to_string().as_bytes()).await,
    }
    Ok(())
}

/// The namespaces this server serves. The two TUF halves, plus the report namespace it also
/// accepts writes into — a namespace this server can write but never read back would 404 every
/// consumer's fetch while each `PUT` reported success.
const SERVED_NAMESPACES: [&str; 3] = [
    "metadata",
    "targets",
    updated_contracts::telemetry::REPORT_NAMESPACE,
];

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
    if !SERVED_NAMESPACES.contains(&namespace) {
        return None;
    }
    out.push(namespace);
    for part in parts {
        // Confined path safety is the one shared guard; a served repository file additionally
        // rejects any dot-leading segment (no `.`/`..` climb and no hidden files).
        if !updated_contracts::path::is_safe_component(part) || part.starts_with('.') {
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

    /// The server accepts report writes, so it must serve them back: a store that knows only the
    /// write half answers 404 to every consumer fetch, and a health proxy pointed at it programs
    /// an empty backend set forever while each `PUT` reports success.
    #[tokio::test]
    async fn a_stored_report_is_served_back_to_the_reader_that_fetches_it() {
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        use updated_contracts::telemetry::{
            report_is_authentic_and_fresh, report_object_key, sign_report, NodeReport,
        };

        let root = serve_root("telemetry-roundtrip");
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let report = NodeReport::new("agent-7", "deploy-3", digest, "3.0.0", digest, true);
        let body = serde_json::to_vec(&sign_report(&report, pkcs8.as_ref()).unwrap()).unwrap();

        let key_path = report_object_key("agent-7");
        let put = format!(
            "PUT /{key_path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8(body.clone()).unwrap()
        );
        let stored = get(&root, &put).await;
        assert!(stored.starts_with("HTTP/1.1 200"), "got: {stored:?}");

        let fetched = get(&root, &format!("GET /{key_path} HTTP/1.1\r\n\r\n")).await;
        assert!(fetched.starts_with("HTTP/1.1 200"), "got: {fetched:?}");
        let (_, served) = fetched.split_once("\r\n\r\n").unwrap();
        assert_eq!(served.as_bytes(), body);
        // The served bytes are still the ones the node signed, not a re-encoding.
        let envelope = serde_json::from_slice(served.as_bytes()).unwrap();
        assert!(report_is_authentic_and_fresh(
            &envelope,
            "agent-7",
            key.public_key().as_ref(),
            updated_contracts::telemetry::now_ms(),
        )
        .is_some());
    }

    /// A client that keeps every individual write inside `write_with_timeout` — draining one
    /// chunk just before each 30s write deadline — would otherwise hold its connection permit for
    /// as long as it likes; 128 of those wedge the accept loop. The overall deadline ends it.
    #[tokio::test(start_paused = true)]
    async fn a_slow_reader_cannot_hold_a_connection_past_the_overall_deadline() {
        let root = serve_root("slow-reader");
        // Larger than a slow reader can drain within the deadline at this rate.
        std::fs::write(root.join("targets/big"), vec![7u8; 4 << 20]).unwrap();

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let root = root.clone();
            async move { serve_conn(server, &root).await }
        });
        client
            .write_all(b"GET /targets/big HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        // Drain slowly enough to outlive the deadline, fast enough that no single 64 KiB write
        // ever hits its own 30s timeout.
        let draining = tokio::spawn(async move {
            let mut sink = [0u8; 64 * 1024];
            loop {
                tokio::time::sleep(Duration::from_secs(25)).await;
                if client.read(&mut sink).await.unwrap_or(0) == 0 {
                    return;
                }
            }
        });

        let error = served
            .await
            .unwrap()
            .expect_err("a connection past the overall deadline must be dropped");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "got: {error}");
        draining.abort();
        std::fs::remove_dir_all(root).unwrap();
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

    /// The signed runtime policy an assignment carries. Valid, because `publish-assignment`
    /// validates it before it stages anything.
    fn managed_runtime() -> updated_contracts::assignment::ManagedRuntime {
        use updated_contracts::assignment::*;
        ManagedRuntime {
            mode: RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: Default::default(),
            repository: ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 30,
            },
            storage: ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1 << 30,
                inactive_repository_caches: 2,
            },
            timeouts: ManagedTimeouts {
                check_interval_seconds: 15,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                retry_after_seconds: 60,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    /// A publish stages the documents it is about to sign under fixed names in the shared
    /// repository directory, so the staging write belongs INSIDE the publisher lock. Staged before
    /// it, a concurrent publisher's bytes land in `.config-build.json` between this process's write
    /// and `add_release` hashing it — each then signs the other's document, and the cleanup at the
    /// end deletes the other publisher's staging file out from under it.
    #[test]
    fn assignment_staging_waits_for_the_publisher_lock() {
        let root =
            std::env::temp_dir().join(format!("server-publish-staging-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo_dir = root.join("repo");
        let keys_dir = root.join("keys");
        std::fs::create_dir_all(&repo_dir).unwrap();
        let runtime_path = root.join("runtime.json");
        std::fs::write(
            &runtime_path,
            serde_json::to_vec(&managed_runtime()).unwrap(),
        )
        .unwrap();

        let runner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let keys = runner.block_on(repo::generate_keys(&keys_dir)).unwrap();
        runner.block_on(repo::init(&repo_dir, &keys, 365)).unwrap();

        let digest = "a".repeat(64);
        let args: Vec<String> = vec![
            "--repo".into(),
            repo_dir.display().to_string(),
            "--keys".into(),
            keys_dir.display().to_string(),
            "--name".into(),
            "assignments/agents/agent-0.json".into(),
            "--metadata-url".into(),
            "https://cdn/metadata/".into(),
            "--targets-url".into(),
            "https://cdn/targets/".into(),
            "--deployment".into(),
            "deploy-1".into(),
            "--application-path".into(),
            "products/app".into(),
            "--application-sha256".into(),
            digest.clone(),
            "--provider-set-path".into(),
            "provider-sets/set.json".into(),
            "--provider-set-sha256".into(),
            digest,
            "--runtime".into(),
            runtime_path.display().to_string(),
        ];

        // Stand in for the concurrent publisher: hold the lock while this publish runs.
        let held = lock_publisher(&repo_dir).unwrap();
        let staged = repo_dir.join(".config-build.json");
        let publishing = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    publish_assignment(&args)
                        .await
                        .map_err(|error| error.to_string())
                })
        });

        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !staged.exists(),
            "a publish staged the bytes it signs while another publisher held the lock"
        );

        drop(held);
        publishing
            .join()
            .unwrap()
            .expect("the publish completes once the lock is released");
        assert!(
            !staged.exists(),
            "staging is cleaned up once the release is signed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
