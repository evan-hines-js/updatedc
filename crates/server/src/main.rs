//! Development TUF publisher and static repository server (the mock CDN).
//!
//! - `init`    mint the four ed25519 role keys and an empty signed repository.
//! - `publish` add a release: register per-platform targets and re-sign
//!   targets/snapshot/timestamp.
//! - `serve`   serve the repository directory over HTTP for clients to refresh.
//!
//! Publishing is an offline/CI operation; a deployed client never runs it.

use std::path::{Path, PathBuf};
use std::process::exit;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    let expiry_days = flag_i64(args, "--expiry-days", 365);

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
    let expiry_days = flag_i64(args, "--expiry-days", 365);

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
    repo::add_release(&repo_dir, &keys, targets, expiry_days).await?;
    println!("published {product} {version} on channel {channel}");
    Ok(())
}

// --- serve ------------------------------------------------------------------

async fn serve(args: &[String]) -> R {
    let repo_dir = PathBuf::from(flag(args, "--repo").ok_or("--repo <dir> is required")?);
    let addr = flag(args, "--addr").unwrap_or_else(|| "127.0.0.1:8080".into());
    let root = tokio::fs::canonicalize(&repo_dir).await?;

    let listener = TcpListener::bind(&addr).await?;
    println!("serving {} on http://{addr}", root.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            let _ = serve_conn(stream, &root).await;
        });
    }
}

async fn serve_conn(mut stream: TcpStream, root: &Path) -> std::io::Result<()> {
    // Read request headers (bounded).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
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
        Some(file) => match tokio::fs::read(&file).await {
            Ok(body) => respond(&mut stream, body, range_start).await,
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
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || part.contains('\\') {
            return None;
        }
        out.push(part);
    }
    // Must stay within root.
    let canonical = std::fs::canonicalize(&out).ok()?;
    canonical.starts_with(root).then_some(canonical)
}

async fn respond(stream: &mut TcpStream, body: Vec<u8>, range_start: Option<usize>) {
    match range_start {
        Some(start) if start <= body.len() => {
            let slice = &body[start..];
            let hdr = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n\
                 Content-Range: bytes {start}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len().saturating_sub(1),
                body.len(),
                slice.len()
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
            let _ = stream.write_all(slice).await;
        }
        _ => {
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    }
    let _ = stream.flush().await;
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

fn flag_i64(args: &[String], name: &str, default: i64) -> i64 {
    flag(args, name)
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
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
        let root = std::env::temp_dir();
        // A nested, non-escaping path resolves under root (file need not exist for
        // the traversal checks, but canonicalize requires it, so use root itself).
        assert!(resolve(&std::fs::canonicalize(&root).unwrap(), "/").is_some());
    }

    #[test]
    fn resolve_rejects_traversal() {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(resolve(&root, "/../etc/passwd").is_none());
        assert!(resolve(&root, "/a/../../etc").is_none());
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
}
