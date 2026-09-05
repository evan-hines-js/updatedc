#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Development TUF publisher and explicit private-capability/public-object fixtures.
//!
//! - `init`    mint the five ed25519 role keys and an empty signed repository.
//! - `publish-app` build and publish application bundles.
//! - `publish-assignment` publish an exact desired deployment last.
//! - `export-enrollment` write the enrollment bundle a node boots from.
//! - `target-sha256` print the content address of a published target.
//! - `gen-certs` mint the development mTLS certificate hierarchy.
//! - `serve-capability` serve a private repository through exact bearer capabilities.
//! - `serve-object` serve a public release repository as an anonymous HTTPS object origin.
//!
//! Publishing is an offline/CI operation; a deployed client never runs it.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use updated_tuf::repo::{self, PublishTarget};

mod certs;

type R = Result<(), Box<dyn std::error::Error>>;

fn read_operator_file(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    foundation::file::read_bounded_regular(path, limit, foundation::file::FinalSymlink::Follow)
}

fn read_operator_text(path: &Path, limit: usize) -> std::io::Result<String> {
    foundation::file::read_bounded_regular_string(
        path,
        limit,
        foundation::file::FinalSymlink::Follow,
    )
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    let result = match cmd {
        "init" => init(rest).await,
        "publish-app" => publish(rest).await,
        "publish-assignment" => publish_assignment(rest).await,
        "export-enrollment" => export_enrollment(rest),
        "target-sha256" => target_sha256(rest).await,
        "gen-certs" => gen_certs(rest).await,
        "serve-capability" => serve(rest, ServeKind::Capability).await,
        "serve-object" => serve(rest, ServeKind::Object).await,
        other => {
            eprintln!("unknown or missing subcommand: {other:?}");
            eprintln!(
                "usage: server <init|publish-app|publish-assignment|export-enrollment|target-sha256|gen-certs|serve-capability|serve-object> [flags]"
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
    let limit = updated_contracts::enrollment::MAX_DOCUMENT_BYTES;
    let root = read_operator_text(&metadata.join("root.json"), limit)?;
    let timestamp = read_operator_text(&metadata.join("timestamp.json"), limit)?;
    let timestamp_value: serde_json::Value = serde_json::from_str(&timestamp)?;
    let snapshot_version = timestamp_value
        .pointer("/signed/meta/snapshot.json/version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("timestamp omits snapshot.json version")?;
    let snapshot = read_operator_text(
        &metadata.join(format!("{snapshot_version}.snapshot.json")),
        limit,
    )?;
    let snapshot_value: serde_json::Value = serde_json::from_str(&snapshot)?;
    let targets_version = snapshot_value
        .pointer("/signed/meta/targets.json/version")
        .and_then(serde_json::Value::as_u64)
        .ok_or("snapshot omits targets.json version")?;
    let targets = read_operator_text(
        &metadata.join(format!("{targets_version}.targets.json")),
        limit,
    )?;
    let targets_value: serde_json::Value = serde_json::from_str(&targets)?;
    let agent_document = repository_target_text(&repo, &targets_value, &assignment)?;
    let agent: updated_contracts::artifact::AgentDocument = serde_json::from_str(&agent_document)?;
    agent.validate()?;
    let managed_configuration = repository_target_text(&repo, &targets_value, &agent.config.path)?;
    // Export and online enrollment share this one complete TUF-verification path. Reading files
    // from an operator-supplied repository is not itself proof that the metadata roles, hashes,
    // target lengths, assignment binding, or expiries form one authentic publication.
    let managed = updated_tuf::verify_enrollment_publication(
        root.as_bytes(),
        timestamp.as_bytes(),
        snapshot.as_bytes(),
        targets.as_bytes(),
        &assignment,
        agent_document.as_bytes(),
        managed_configuration.as_bytes(),
    )?;
    let bundle = updated_contracts::enrollment::EnrollmentBundle {
        schema: 1,
        agent_id: updated_contracts::identity::ResourceName::new(agent_id)?,
        routing_base_url: ensure_base_location(routing_base_url),
        assignment,
        install_root: managed.runtime.install_root,
        routing_root: root,
    };
    bundle.validate_shape()?;
    foundation::durable::atomic_write(&output, ".enrollment-", &bundle.to_bounded_json()?)?;
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
    Ok(read_operator_text(
        &repo.join("targets").join(format!("{sha}.{logical}")),
        updated_contracts::enrollment::MAX_DOCUMENT_BYTES,
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
    let cold_install_fallback = args.iter().any(|arg| arg == "--cold-install-fallback");
    // Routing and releases are deliberately different repositories: the former is private and
    // capability-gated, while the latter is fetched directly from the object plane. Requiring the
    // release root makes that trust boundary explicit and prevents a fixture or operator tool from
    // silently signing the routing repository's root as though it authenticated release bytes.
    let release_root_path = PathBuf::from(
        flag(args, "--release-root").ok_or("--release-root <root.json> is required")?,
    );
    let release_root = serde_json::from_slice(&read_operator_file(
        &release_root_path,
        updated_contracts::assignment::RepositoryAssignment::MAX_DOCUMENT_BYTES,
    )?)?;
    let runtime_path = flag(args, "--runtime").ok_or("--runtime <runtime.json> is required")?;
    let runtime = serde_json::from_slice(&read_operator_file(
        Path::new(&runtime_path),
        updated_contracts::assignment::RepositoryAssignment::MAX_DOCUMENT_BYTES,
    )?)?;
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;
    let config_source = repo_dir.join(".config-build.json");
    let node_source = repo_dir.join(".node-build.json");
    let assignment = updated_contracts::assignment::RepositoryAssignment {
        schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
        deployment,
        metadata_url,
        targets_url,
        application,
        cold_install_fallback,
        release_root,
        runtime,
    };
    let (config_bytes, config_sha256) = assignment.publication()?;
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
    let keys = repo::Keys::in_dir(&keys_dir)?;
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

fn target_reference(
    args: &[String],
    prefix: &str,
) -> Result<updated_contracts::artifact::TargetReference, Box<dyn std::error::Error>> {
    let path = flag(args, &format!("--{prefix}-path"))
        .ok_or_else(|| format!("--{prefix}-path <target> is required"))?;
    let sha256 = flag(args, &format!("--{prefix}-sha256"))
        .ok_or_else(|| format!("--{prefix}-sha256 <hex> is required"))?;
    let sha256 = updated_contracts::digest::parse_canonical_sha256(&sha256)
        .map_err(|error| format!("--{prefix}-sha256: {error}"))?;
    Ok(updated_contracts::artifact::TargetReference { path, sha256 })
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

async fn publish(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let keys_dir = PathBuf::from(flag(args, "--keys").ok_or("--keys <dir> is required")?);
    let product = flag(args, "--product").ok_or("--product <name> is required")?;
    let channel = flag(args, "--channel").unwrap_or_else(|| "stable".into());
    let version = flag(args, "--version").ok_or("--version <semver> is required")?;
    updated_contracts::identity::parse_release_version(&version)
        .ok_or("invalid --version: expected a bounded semantic version")?;
    for (flag, value) in [
        ("--product", product.as_str()),
        ("--channel", channel.as_str()),
    ] {
        if !updated_contracts::identity::is_segment(value) {
            return Err(format!("{flag} is not a valid identity segment: {value:?}").into());
        }
    }
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;

    let artifact_flag = "--bundle";
    let raw = flags_all(args, artifact_flag);
    if raw.is_empty() {
        return Err(format!("at least one {artifact_flag} <os>-<arch>=<path> is required").into());
    }
    let keys = repo::Keys::in_dir(&keys_dir)?;
    let _publish_lock = lock_publisher(&repo_dir)?;
    let bundle_scratch = BundleBuildScratch::create(&repo_dir)?;

    let mut targets = Vec::new();
    for (target_index, t) in raw.iter().enumerate() {
        let (platform, source) = t
            .split_once('=')
            .ok_or_else(|| format!("{artifact_flag} must be <os>-<arch>=<path>, got {t:?}"))?;
        let (os, arch) = platform
            .split_once('-')
            .ok_or_else(|| format!("platform must be <os>-<arch>, got {platform:?}"))?;
        for (part, value) in [("os", os), ("arch", arch)] {
            if !updated_contracts::identity::is_segment(value) {
                return Err(format!("platform {part} is invalid in {platform:?}").into());
            }
        }
        let scratch = bundle_scratch.path();
        let path = scratch.join(format!("{target_index}.tar.zst"));
        updated::command_adapter::inspect_package(Path::new(source))?;
        updated::bundle::create_bundle(Path::new(source), &path, &product, &version, platform)?;

        // Test-only: deliberately damage the just-built archive. It is corrupted *before*
        // `add_release` hashes it, so the published target is signed for its own broken bytes —
        // it passes the client's download sha check and fails only at extract/validate. This is
        // the malformed-but-signed bundle an honest publisher can never emit, used to exercise
        // the client's ingest-rejection + cold-install-fallback descent. Never used by real releases.
        if let Some(kind) = flag(args, "--corrupt") {
            corrupt_archive(&path, &kind, &version)?;
        }
        targets.push(PublishTarget::application(
            &product, &channel, &version, os, arch, &product, path,
        ));
    }

    for t in &targets {
        println!("  {}", t.name);
    }

    repo::add_release(&repo_dir, &keys, targets, expiry_days).await?;
    println!("published {product} {version} on channel {channel}");
    Ok(())
}

/// One publish invocation's bundle workspace. The namespace is fixed and owned by this command,
/// the publisher lock excludes concurrent users, and every exit removes it. No user-supplied
/// product/platform text participates in a local path.
struct BundleBuildScratch {
    path: PathBuf,
}

impl BundleBuildScratch {
    fn create(repo_dir: &Path) -> std::io::Result<Self> {
        let path = repo_dir.join(".bundle-build");
        foundation::durable::remove_path(&path)?;
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BundleBuildScratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
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
            let file = OpenOptions::new().write(true).open(archive)?;
            file.set_len(file.metadata()?.len() / 2)?;
            file.sync_all()?;
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
    let lock = foundation::file::open_lock_file(
        &repo_dir.join(".publish.lock"),
        foundation::file::LockFileDisposition::OpenOrCreate,
    )?;
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

#[derive(Clone, Copy)]
enum ServeKind {
    Capability,
    Object,
}

#[derive(Clone)]
struct CapabilityStore {
    public_url: Arc<str>,
    grants: Arc<Mutex<HashMap<String, CapabilityGrant>>>,
}

#[derive(Clone)]
struct CapabilityGrant {
    path: String,
    expires: Instant,
}

const MAX_FIXTURE_CAPABILITIES: usize = 4096;

async fn serve(args: &[String], kind: ServeKind) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let addr = flag(args, "--addr").unwrap_or_else(|| "127.0.0.1:8080".into());
    let root = tokio::fs::canonicalize(&repo_dir).await?;

    let cert = PathBuf::from(flag(args, "--cert").ok_or("--cert <server.crt> is required")?);
    let key = PathBuf::from(flag(args, "--key").ok_or("--key <server.key> is required")?);
    let (tls, capabilities) = match kind {
        ServeKind::Capability => {
            let ca = PathBuf::from(flag(args, "--ca").ok_or("--ca <ca.crt> is required")?);
            let public_url =
                flag(args, "--public-url").ok_or("--public-url <https-url> is required")?;
            let parsed = updated_contracts::endpoint::https_origin(&public_url).map_err(|_| {
                "--public-url must be an HTTPS origin with no path, query, or fragment"
            })?;
            let public_url: Arc<str> = parsed.as_str().trim_end_matches('/').into();
            (
                updated::tls::capability_fixture_server_config(&cert, &key, &ca)?,
                Some(CapabilityStore {
                    public_url,
                    grants: Arc::new(Mutex::new(HashMap::new())),
                }),
            )
        }
        ServeKind::Object => (
            updated::tls::object_fixture_server_config(&cert, &key)?,
            None,
        ),
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(&addr).await?;
    let bound = listener.local_addr()?;
    let connections = Arc::new(Semaphore::new(128));
    match kind {
        ServeKind::Capability => println!(
            "serving capability repository {} on https://{bound}",
            root.display()
        ),
        ServeKind::Object => println!(
            "serving object repository {} on https://{bound}",
            root.display()
        ),
    }
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
        let capabilities = capabilities.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // The handshake is bounded like every other phase. Without it a client that opens a
            // connection and sends nothing holds its permit forever; 128 of those exhaust the
            // semaphore, the accept loop blocks on `acquire_owned`, and the server stops serving
            // entirely — no error, no recovery.
            if let Ok(Ok(stream)) = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                let authenticated = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .is_some_and(|certificates| !certificates.is_empty());
                let access = match capabilities {
                    Some(store) => RequestAccess::Capability {
                        authenticated,
                        store,
                    },
                    None => RequestAccess::Object,
                };
                let _ = serve_conn(stream, &root, access).await;
            }
        });
    }
}

/// How long a client has to complete the TLS handshake while holding a connection permit.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a handshaken client has to finish its one request while holding a connection permit.
///
/// Every individual phase is already bounded — the header read and each
/// `write_all` — but per-operation bounds do not bound the connection: a client that drains one
/// 64 KiB chunk every ~25s keeps every write inside `write_with_timeout` forever and holds its
/// permit indefinitely. 128 such connections exhaust the semaphore, the accept loop blocks on
/// `acquire_owned`, and the server stops serving entirely — the same wedge `HANDSHAKE_TIMEOUT`
/// exists to prevent, just moved past the handshake. Generous enough that an honest agent pulling
/// the largest target off this loopback CDN never trips it.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// Serve the connection's one request under an overall deadline, so a permit's lifetime is bounded
/// by `HANDSHAKE_TIMEOUT + CONNECTION_TIMEOUT` no matter how the peer behaves.
#[derive(Clone)]
enum RequestAccess {
    Capability {
        authenticated: bool,
        store: CapabilityStore,
    },
    Object,
}

async fn serve_conn<S>(stream: S, root: &Path, access: RequestAccess) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(CONNECTION_TIMEOUT, serve_request(stream, root, access))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connection deadline"))?
}

async fn serve_request<S>(mut stream: S, root: &Path, access: RequestAccess) -> std::io::Result<()>
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
    if method != "GET" {
        respond_status(&mut stream, 405, b"method not allowed").await;
        return Ok(());
    }
    // A `Range` header means a client is resuming (or slicing) a download. This fixture implements
    // the direct object-store hop, so its one range parser lives in the shared repository-serving
    // support module rather than being restated here.
    let header_value = head.lines().skip(1).find_map(|line| {
        let lowered = line.to_ascii_lowercase();
        lowered
            .strip_prefix("range:")
            .map(|value| value.trim().to_owned())
    });
    let range = match header_value
        .as_deref()
        .map(updatec::served::parse_range_value)
    {
        None => None,
        Some(Some(range)) => Some(range),
        Some(None) => {
            respond_status(&mut stream, 400, b"malformed range").await;
            return Ok(());
        }
    };

    let object_path = match access {
        RequestAccess::Object => Some(path.to_owned()),
        RequestAccess::Capability {
            authenticated: true,
            store,
        } => {
            // Do not mint a bearer for a path this origin would not serve. Besides producing a
            // truthful 404, this keeps the grant table from becoming an authenticated arbitrary
            // string store.
            let Some(file) = open_repository_file(root, path) else {
                respond_status(&mut stream, 404, b"not found").await;
                return Ok(());
            };
            drop(file);
            match store.mint(path) {
                Ok(location) => respond_redirect(&mut stream, &location).await,
                Err(_) => respond_status(&mut stream, 503, b"capability capacity exhausted").await,
            }
            return Ok(());
        }
        RequestAccess::Capability {
            authenticated: false,
            store,
        } => store.authorize(path),
    };
    let Some(object_path) = object_path else {
        // Deliberately do not distinguish malformed, expired, unknown, or wrong-object bearers.
        respond_status(&mut stream, 403, b"invalid object capability").await;
        return Ok(());
    };

    match open_repository_file(root, &object_path) {
        Some(file) => respond_file(&mut stream, tokio::fs::File::from_std(file), range).await,
        None => respond_status(&mut stream, 404, b"not found").await,
    }
    Ok(())
}

impl CapabilityStore {
    fn mint(&self, path: &str) -> std::io::Result<String> {
        let now = Instant::now();
        let mut grants = self
            .grants
            .lock()
            .map_err(|_| std::io::Error::other("capability store poisoned"))?;
        grants.retain(|_, grant| grant.expires > now);
        if grants.len() >= MAX_FIXTURE_CAPABILITIES {
            return Err(std::io::Error::other("capability capacity exhausted"));
        }
        let token = updated::rand::token()?;
        grants.insert(
            token.clone(),
            CapabilityGrant {
                path: path.to_owned(),
                expires: now + updated_contracts::dataflow::OBJECT_CAPABILITY_TTL,
            },
        );
        Ok(format!("{}{path}?cap={token}", self.public_url))
    }

    fn authorize(&self, request_target: &str) -> Option<String> {
        let (path, query) = request_target.split_once('?')?;
        let token = query.strip_prefix("cap=")?;
        if !updated::rand::is_token(token) {
            return None;
        }
        let now = Instant::now();
        let mut grants = self.grants.lock().ok()?;
        grants.retain(|_, grant| grant.expires > now);
        let grant = grants.get(token)?;
        (grant.path == path).then(|| path.to_owned())
    }
}

async fn respond_redirect<S>(stream: &mut S, location: &str)
where
    S: AsyncWrite + Unpin,
{
    // `location` is assembled only from a validated HTTPS origin, a path accepted by the shared
    // repository grammar, and a fixed-width hex token, so it cannot inject response headers.
    let header = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = write_with_timeout(stream, header.as_bytes()).await;
}

/// The read-only namespaces this development repository serves.
const SERVED_NAMESPACES: [&str; 2] = ["metadata", "targets"];

/// Map a request path to a file inside `root`. Which request paths name a repository object is
/// the repository grammar ([`updatec::served::repository_object`]), shared so these fixtures serve
/// exactly the requests production serves — nested target paths yes, traversal, empty and
/// dot-leading segments, query strings and percent-escapes no. What is added here is the local
/// half: the namespaces this server publishes, and opening the file without letting a symlink
/// swap move the bytes out from under the validated path.
fn open_repository_file(root: &Path, path: &str) -> Option<std::fs::File> {
    let object = updatec::served::repository_object(path)?;
    if !SERVED_NAMESPACES.contains(&object.namespace) {
        return None;
    }
    let mut out = root.to_path_buf();
    out.push(object.namespace);
    for part in object.relative.split('/') {
        out.push(part);
    }
    foundation::file::open_regular_beneath(root, &out, foundation::file::FinalSymlink::Follow).ok()
}

async fn respond_file<S>(
    stream: &mut S,
    mut file: tokio::fs::File,
    range: Option<updatec::served::ByteRange>,
) where
    S: AsyncWrite + Unpin,
{
    // The canonical repository opener admits regular files only. Metadata is read from
    // the already-validated handle so the declared response length describes these bytes.
    let Ok(metadata) = file.metadata().await else {
        respond_status(stream, 404, b"not found").await;
        return;
    };
    let length = metadata.len();
    // Where a range lands over these bytes — including the RFC's clamping of a bounded end past
    // the last byte and of an over-long suffix — is the shared grammar's answer, not a second one.
    let placed = range.map(|range| range.resolve(length));
    if let Some(None) = placed {
        let hdr = format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{length}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = write_with_timeout(stream, hdr.as_bytes()).await;
        return;
    }
    let (header, offset, count) = match placed.flatten() {
        Some((start, count)) => {
            let hdr = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n\
                 Content-Range: bytes {start}-{}/{length}\r\nContent-Length: {count}\r\nConnection: close\r\n\r\n",
                start + count - 1,
            );
            (hdr, start, count)
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
        411 => "Length Required",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn resolve_allows_nested_target_paths() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
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
        let (_tmp, root) = serve_root("escaping-symlink");
        let outside = root.parent().unwrap().join("server-outside-target");
        std::fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("targets/escape")).unwrap();
        assert!(open_repository_file(&root, "/targets/escape").is_none());
        std::fs::remove_file(outside).unwrap();
    }

    /// Serve one request through an in-memory transport so protocol unit tests do not
    /// require permission to bind loopback sockets.
    async fn get(root: &Path, request: &str) -> String {
        serve_one(root, request, RequestAccess::Object).await
    }

    async fn serve_one(root: &Path, request: &str, access: RequestAccess) -> String {
        let (mut client, server) = tokio::io::duplex(32 * 1024);
        let root = root.to_path_buf();
        tokio::spawn(async move {
            let _ = serve_conn(server, &root, access).await;
        });
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn serve_root(name: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let root = guard.path().join(name);
        std::fs::create_dir_all(root.join("targets")).unwrap();
        std::fs::create_dir_all(root.join("metadata")).unwrap();
        std::fs::write(root.join("targets/app"), b"0123456789").unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        (guard, root)
    }

    #[tokio::test]
    async fn a_directory_is_not_a_body() {
        // `File::open` on a directory succeeds on Unix and stats non-zero, which would
        // otherwise answer 200 with a Content-Length and then zero bytes.
        let (_tmp, root) = serve_root("dir");
        let response = get(&root, "GET /metadata HTTP/1.1\r\n\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "a directory must 404, got: {response:?}"
        );
    }

    #[tokio::test]
    async fn the_body_matches_the_declared_content_length() {
        let (_tmp, root) = serve_root("exact");
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
        let (_tmp, root) = serve_root("resume");
        let response = get(
            &root,
            "GET /targets/app HTTP/1.1\r\nRange: bytes=4-\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 206"), "got: {response:?}");
        assert!(response.contains("Content-Length: 6"), "got: {response:?}");
        assert!(response.ends_with("456789"), "got: {response:?}");
    }

    /// A bounded and a suffix range are what production serves; while this server open-coded its
    /// own range parser it answered both with a 400, so no run ever exercised production's rule.
    #[tokio::test]
    async fn bounded_and_suffix_ranges_match_direct_object_storage() {
        let (_tmp, root) = serve_root("range-shapes");
        for (header, expected_range, body) in [
            ("bytes=0-3", "bytes 0-3/10", "0123"),
            ("bytes=8-99", "bytes 8-9/10", "89"),
            ("bytes=-3", "bytes 7-9/10", "789"),
            ("bytes=-99", "bytes 0-9/10", "0123456789"),
        ] {
            let response = get(
                &root,
                &format!("GET /targets/app HTTP/1.1\r\nRange: {header}\r\n\r\n"),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 206"), "got: {response:?}");
            assert!(
                response.contains(&format!("Content-Range: {expected_range}")),
                "{header} got: {response:?}"
            );
            assert!(response.ends_with(body), "{header} got: {response:?}");
        }
    }

    /// The one length at which a suffix range has nothing to place. This verifies the fixture's
    /// direct-object behavior; the production gateway does not inspect or proxy range requests.
    #[tokio::test]
    async fn a_suffix_range_over_an_empty_object_is_not_satisfiable() {
        let (_tmp, root) = serve_root("empty-suffix");
        std::fs::write(root.join("targets/empty"), b"").unwrap();
        let response = get(
            &root,
            "GET /targets/empty HTTP/1.1\r\nRange: bytes=-500\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 416"), "got: {response:?}");
        assert!(
            response.contains("Content-Range: bytes */0"),
            "got: {response:?}"
        );
    }

    #[tokio::test]
    async fn unsupported_methods_are_rejected() {
        let (_tmp, root) = serve_root("method");
        let response = get(&root, "POST /targets/app HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405"), "got: {response:?}");
    }

    #[tokio::test]
    async fn capability_gateway_requires_identity_then_binds_the_bearer_to_one_object() {
        let (_tmp, root) = serve_root("capability");
        let store = CapabilityStore {
            public_url: "https://objects.example".into(),
            grants: Arc::new(Mutex::new(HashMap::new())),
        };
        let denied = serve_one(
            &root,
            "GET /targets/app HTTP/1.1\r\n\r\n",
            RequestAccess::Capability {
                authenticated: false,
                store: store.clone(),
            },
        )
        .await;
        assert!(denied.starts_with("HTTP/1.1 403"), "got: {denied:?}");

        let minted = serve_one(
            &root,
            "GET /targets/app HTTP/1.1\r\n\r\n",
            RequestAccess::Capability {
                authenticated: true,
                store: store.clone(),
            },
        )
        .await;
        assert!(minted.starts_with("HTTP/1.1 307"), "got: {minted:?}");
        let location = minted
            .lines()
            .find_map(|line| line.strip_prefix("Location: "))
            .unwrap();
        let request_target = location.strip_prefix("https://objects.example").unwrap();
        let body = serve_one(
            &root,
            &format!("GET {request_target} HTTP/1.1\r\n\r\n"),
            RequestAccess::Capability {
                authenticated: false,
                store: store.clone(),
            },
        )
        .await;
        assert!(body.starts_with("HTTP/1.1 200"), "got: {body:?}");
        assert!(body.ends_with("0123456789"), "got: {body:?}");

        let token = request_target.split_once('?').unwrap().1;
        let wrong = serve_one(
            &root,
            &format!("GET /metadata/root.json?{token} HTTP/1.1\r\n\r\n"),
            RequestAccess::Capability {
                authenticated: false,
                store,
            },
        )
        .await;
        assert!(wrong.starts_with("HTTP/1.1 403"), "got: {wrong:?}");
    }

    #[tokio::test]
    async fn malformed_ranges_are_rejected() {
        let (_tmp, root) = serve_root("bad-range");
        let response = get(
            &root,
            "GET /targets/app HTTP/1.1\r\nRange: bytes=wat\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"), "got: {response:?}");
    }

    #[tokio::test]
    async fn a_range_at_eof_is_unsatisfiable() {
        let (_tmp, root) = serve_root("eof-range");
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
        let (_tmp, root) = serve_root("large-header");
        let request = format!(
            "GET /targets/app HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
            "x".repeat(16 * 1024)
        );
        let response = get(&root, &request).await;
        assert!(response.starts_with("HTTP/1.1 431"), "got: {response:?}");
    }

    /// A client that keeps every individual write inside `write_with_timeout` — draining one
    /// chunk just before each 30s write deadline — would otherwise hold its connection permit for
    /// as long as it likes; 128 of those wedge the accept loop. The overall deadline ends it.
    #[tokio::test(start_paused = true)]
    async fn a_slow_reader_cannot_hold_a_connection_past_the_overall_deadline() {
        let (_tmp, root) = serve_root("slow-reader");
        // Larger than a slow reader can drain within the deadline at this rate.
        std::fs::write(root.join("targets/big"), vec![7u8; 4 << 20]).unwrap();

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let root = root.clone();
            async move { serve_conn(server, &root, RequestAccess::Object).await }
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
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().to_path_buf();

        let first = lock_publisher(&dir).unwrap();
        let second = foundation::file::open_lock_file(
            &dir.join(".publish.lock"),
            foundation::file::LockFileDisposition::OpenExisting,
        )
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

    #[cfg(unix)]
    #[test]
    fn publisher_lock_never_follows_a_redirected_name() {
        let scratch = tempfile::tempdir().unwrap();
        let victim = scratch.path().join("victim");
        let lock = scratch.path().join(".publish.lock");
        std::fs::write(&victim, b"not a repository lock").unwrap();
        std::os::unix::fs::symlink(&victim, &lock).unwrap();

        assert!(lock_publisher(scratch.path()).is_err());
        assert_eq!(std::fs::read(victim).unwrap(), b"not a repository lock");
    }

    /// The signed runtime policy an assignment carries. Valid, because `publish-assignment`
    /// validates it before it stages anything.
    fn managed_runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::testing::runtime()
    }

    /// A publish stages the documents it is about to sign under fixed names in the shared
    /// repository directory, so the staging write belongs INSIDE the publisher lock. Staged before
    /// it, a concurrent publisher's bytes land in `.config-build.json` between this process's write
    /// and `add_release` hashing it — each then signs the other's document, and the cleanup at the
    /// end deletes the other publisher's staging file out from under it.
    #[test]
    fn assignment_staging_waits_for_the_publisher_lock() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
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
            "--release-root".into(),
            repo_dir.join("metadata/root.json").display().to_string(),
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
