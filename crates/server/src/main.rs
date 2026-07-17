//! Development TUF publisher and static repository server (the mock CDN).
//!
//! - `init`    mint the four ed25519 role keys and an empty signed repository.
//! - `publish` add a release: register per-platform targets and re-sign
//!   targets/snapshot/timestamp.
//! - `serve`   serve the repository directory over HTTP for clients to refresh.
//!
//! Publishing is an offline/CI operation; a deployed client never runs it.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use updated_tuf::repo::{self, PublishTarget};

type R = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    let result = match cmd {
        "init" => init(rest).await,
        "publish" => publish(rest).await,
        "serve" => serve(rest).await,
        other => {
            eprintln!("unknown or missing subcommand: {other:?}");
            eprintln!("usage: server <init|publish|serve> [flags]");
            exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        exit(1);
    }
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
    semver::Version::parse(&version).map_err(|e| format!("invalid --version: {e}"))?;
    let component = flag(args, "--component").unwrap_or_else(|| product.clone());
    let expiry_days = flag_i64(args, "--expiry-days", 365)?;

    // `--target <os>-<arch>=<path>`, repeatable.
    let raw = flags_all(args, "--target");
    if raw.is_empty() {
        return Err("at least one --target <os>-<arch>=<path> is required".into());
    }
    let keys = repo::Keys::in_dir(&keys_dir);

    let mut targets = Vec::new();
    for t in &raw {
        let (platform, path) = t
            .split_once('=')
            .ok_or_else(|| format!("--target must be <os>-<arch>=<path>, got {t:?}"))?;
        let (os, arch) = platform
            .split_once('-')
            .ok_or_else(|| format!("platform must be <os>-<arch>, got {platform:?}"))?;
        targets.push(PublishTarget::application(
            &product,
            &channel,
            &version,
            os,
            arch,
            &component,
            PathBuf::from(path),
        ));
    }

    for t in &targets {
        println!("  {}", t.name);
    }

    // `publish` is commonly invoked as many short-lived CLI processes (the
    // smoke fuzzer does exactly that), so an in-process mutex is insufficient.
    // Keep the development server's single-writer policy here rather than in
    // the reusable TUF authoring library.
    let _publish_lock = lock_publisher(&repo_dir)?;
    repo::add_release(&repo_dir, &keys, targets, expiry_days).await?;
    println!("published {product} {version} on channel {channel}");
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

async fn serve(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let addr = flag(args, "--addr").unwrap_or_else(|| "127.0.0.1:8080".into());
    let root = tokio::fs::canonicalize(&repo_dir).await?;

    let listener = TcpListener::bind(&addr).await?;
    let connections = Arc::new(Semaphore::new(128));
    println!("serving {} on http://{addr}", root.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = connections.clone().acquire_owned().await?;
        let root = root.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = serve_conn(stream, &root).await;
        });
    }
}

async fn serve_conn(mut stream: TcpStream, root: &Path) -> std::io::Result<()> {
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
    let head = String::from_utf8_lossy(&buf);
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    // A `Range: bytes=N-` header means tough is resuming a download.
    let range_start = head.lines().find_map(|l| {
        let l = l.to_ascii_lowercase();
        l.strip_prefix("range:")
            .and_then(|v| v.trim().strip_prefix("bytes="))
            .and_then(|v| v.split('-').next())
            .and_then(|v| v.trim().parse::<usize>().ok())
    });

    match resolve(root, path) {
        Some(file) => match tokio::fs::File::open(&file).await {
            Ok(file) => respond_file(&mut stream, file, range_start).await,
            Err(_) => respond_status(&mut stream, 404, b"not found").await,
        },
        None => respond_status(&mut stream, 404, b"not found").await,
    }
    Ok(())
}

/// Map a request path to a file inside `root`, rejecting traversal. Slashes are
/// allowed (TUF target paths are nested); `..` components and absolute escapes
/// are not.
fn resolve(root: &Path, path: &str) -> Option<PathBuf> {
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
    // Must stay within root.
    let canonical = std::fs::canonicalize(&out).ok()?;
    canonical.starts_with(root).then_some(canonical)
}

async fn respond_file(
    stream: &mut TcpStream,
    mut file: tokio::fs::File,
    range_start: Option<usize>,
) {
    let Ok(length) = file.metadata().await.map(|m| m.len()) else {
        respond_status(stream, 404, b"not found").await;
        return;
    };
    let start = range_start.map(|n| n as u64).filter(|&n| n <= length);
    let (header, offset) = match start {
        Some(start) => {
            let remaining = length - start;
            let hdr = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n\
                 Content-Range: bytes {start}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                length.saturating_sub(1),
                length,
                remaining
            );
            (hdr, start)
        }
        _ => {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                length
            );
            (hdr, 0)
        }
    };
    if file.seek(std::io::SeekFrom::Start(offset)).await.is_err()
        || write_with_timeout(stream, header.as_bytes()).await.is_err()
    {
        return;
    }
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let Ok(n) = file.read(&mut chunk).await else {
            return;
        };
        if n == 0 || write_with_timeout(stream, &chunk[..n]).await.is_err() {
            break;
        }
    }
    let _ = stream.flush().await;
}

async fn write_with_timeout(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    timeout(Duration::from_secs(30), stream.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response write timeout"))?
}

async fn respond_status(stream: &mut TcpStream, code: u16, body: &[u8]) {
    let reason = if code == 200 { "OK" } else { "Not Found" };
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
        assert!(resolve(&root, "/targets/products/app").is_some());
        assert!(resolve(&root, "/metadata").is_some());
    }

    #[test]
    fn resolve_rejects_traversal() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(resolve(&root, "/../etc/passwd").is_none());
        assert!(resolve(&root, "/a/../../etc").is_none());
        assert!(resolve(&root, "/.publish.lock").is_none());
        assert!(resolve(&root, "/keys/root.pk8").is_none());
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
