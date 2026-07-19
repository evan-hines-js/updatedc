//! Read-only HTTP data plane for repositories published by `updatec`.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{GetOptions, GetRange, ObjectStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

const HEADER_LIMIT: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn serve(
    address: &str,
    store: Arc<dyn ObjectStore>,
    prefix: String,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(address).await?;
    let connections = Arc::new(Semaphore::new(256));
    tracing::info!(%address, "repository gateway listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = connections
            .clone()
            .acquire_owned()
            .await
            .map_err(std::io::Error::other)?;
        let store = store.clone();
        let prefix = prefix.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = serve_connection(stream, store.as_ref(), &prefix).await {
                tracing::warn!(%peer, %error, "gateway request failed");
            }
        });
    }
}

async fn serve_connection<S>(
    mut stream: S,
    store: &dyn ObjectStore,
    prefix: &str,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    timeout(IO_TIMEOUT, async {
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") || request.len() > HEADER_LIMIT
            {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request timeout"))??;

    if request.len() > HEADER_LIMIT {
        return status(&mut stream, 431, "Request Header Fields Too Large").await;
    }
    if !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        return status(&mut stream, 400, "Bad Request").await;
    }
    let Ok(head) = std::str::from_utf8(&request) else {
        return status(&mut stream, 400, "Bad Request").await;
    };
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let (Some(method), Some(path), Some(version), None) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return status(&mut stream, 400, "Bad Request").await;
    };
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return status(&mut stream, 400, "Bad Request").await;
    }
    if !matches!(method, "GET" | "HEAD") {
        return status(&mut stream, 405, "Method Not Allowed").await;
    }
    if path == "/healthz" {
        return response(&mut stream, 200, "OK", &[], method == "HEAD", None).await;
    }
    let Some(key) = repository_key(prefix, path) else {
        return status(&mut stream, 404, "Not Found").await;
    };
    let range = match parse_range(lines) {
        Ok(range) => range,
        Err(()) => return status(&mut stream, 400, "Bad Request").await,
    };
    if let Some(start) = range {
        let metadata = match timeout(IO_TIMEOUT, store.head(&key)).await {
            Err(_) => return status(&mut stream, 504, "Gateway Timeout").await,
            Ok(Err(object_store::Error::NotFound { .. })) => {
                return status(&mut stream, 404, "Not Found").await;
            }
            Ok(Err(_)) => return status(&mut stream, 502, "Bad Gateway").await,
            Ok(Ok(metadata)) => metadata,
        };
        if start >= metadata.size {
            return range_not_satisfiable(&mut stream, metadata.size).await;
        }
    }
    let options = GetOptions {
        range: range.map(GetRange::Offset),
        head: method == "HEAD",
        ..Default::default()
    };
    let result = match timeout(IO_TIMEOUT, store.get_opts(&key, options)).await {
        Err(_) => return status(&mut stream, 504, "Gateway Timeout").await,
        Ok(Err(object_store::Error::NotFound { .. })) => {
            return status(&mut stream, 404, "Not Found").await;
        }
        Ok(Err(_)) => return status(&mut stream, 502, "Bad Gateway").await,
        Ok(Ok(result)) => result,
    };
    let partial = result.range.start != 0;
    let length = result.range.end.saturating_sub(result.range.start);
    let etag = result.meta.e_tag.as_deref().and_then(safe_etag);
    let mut headers = format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {length}\r\nAccept-Ranges: bytes\r\n"
    );
    if partial {
        headers.push_str(&format!(
            "Content-Range: bytes {}-{}/{}\r\n",
            result.range.start,
            result.range.end.saturating_sub(1),
            result.meta.size
        ));
    }
    if let Some(etag) = etag {
        headers.push_str(&format!("ETag: {etag}\r\n"));
    }
    let code = if partial { 206 } else { 200 };
    let reason = if partial { "Partial Content" } else { "OK" };
    write_all(
        &mut stream,
        format!("HTTP/1.1 {code} {reason}\r\n{headers}Connection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    if method == "GET" {
        let mut body = result.into_stream();
        while let Some(next) = timeout(IO_TIMEOUT, body.next())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "object timeout"))?
        {
            let bytes = next.map_err(std::io::Error::other)?;
            write_all(&mut stream, &bytes).await?;
        }
    }
    Ok(())
}

fn repository_key(prefix: &str, request_path: &str) -> Option<ObjectPath> {
    if request_path.contains(['?', '#', '%', '\\']) || !request_path.starts_with('/') {
        return None;
    }
    let mut parts = request_path[1..].split('/');
    let namespace = parts.next()?;
    if !matches!(namespace, "metadata" | "targets") {
        return None;
    }
    let tail: Vec<_> = parts.collect();
    if tail.is_empty()
        || tail
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == ".." || part.starts_with('.'))
    {
        return None;
    }
    let key = [prefix.trim_matches('/'), namespace, &tail.join("/")]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    ObjectPath::parse(key).ok()
}

fn parse_range<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Option<u64>, ()> {
    let mut found = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            if line.is_empty() {
                continue;
            }
            return Err(());
        };
        if name.eq_ignore_ascii_case("range") {
            if found.is_some() {
                return Err(());
            }
            found = Some(
                value
                    .trim()
                    .strip_prefix("bytes=")
                    .and_then(|value| value.strip_suffix('-'))
                    .and_then(|value| value.parse().ok())
                    .ok_or(())?,
            );
        }
    }
    Ok(found)
}

fn safe_etag(value: &str) -> Option<&str> {
    (!value.contains(['\r', '\n'])).then_some(value)
}

async fn status<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
) -> std::io::Result<()> {
    response(stream, code, reason, reason.as_bytes(), false, None).await
}

async fn range_not_satisfiable<S: AsyncWrite + Unpin>(
    stream: &mut S,
    length: u64,
) -> std::io::Result<()> {
    write_all(
        stream,
        format!(
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{length}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
}

async fn response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
    body: &[u8],
    head: bool,
    extra: Option<&str>,
) -> std::io::Result<()> {
    let headers = extra.unwrap_or_default();
    write_all(
        stream,
        format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await?;
    if !head {
        write_all(stream, body).await?;
    }
    Ok(())
}

async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()> {
    timeout(IO_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response timeout"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use object_store::PutPayload;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn request(request: &str) -> Vec<u8> {
        let store = InMemory::new();
        store
            .put(
                &ObjectPath::from("routing/targets/nested/app"),
                PutPayload::from_static(b"hello"),
            )
            .await
            .unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let request = request.as_bytes().to_vec();
        let task = tokio::spawn(async move {
            serve_connection(server, &store, "routing").await.unwrap();
        });
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_nested_repository_objects() {
        let response = request("GET /targets/nested/app HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"hello"));
    }

    #[tokio::test]
    async fn supports_resume_ranges() {
        let response =
            request("GET /targets/nested/app HTTP/1.1\r\nHost: test\r\nRange: bytes=2-\r\n\r\n")
                .await;
        assert!(response.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
        assert!(response.ends_with(b"llo"));
    }

    #[tokio::test]
    async fn rejects_a_range_at_or_beyond_eof() {
        for start in [5, 6] {
            let response = request(&format!(
                "GET /targets/nested/app HTTP/1.1\r\nHost: test\r\nRange: bytes={start}-\r\n\r\n"
            ))
            .await;
            assert!(response.starts_with(b"HTTP/1.1 416 Range Not Satisfiable\r\n"));
            assert!(response
                .windows(b"Content-Range: bytes */5\r\n".len())
                .any(|window| window == b"Content-Range: bytes */5\r\n"));
        }
    }

    #[tokio::test]
    async fn rejects_non_repository_and_ambiguous_paths() {
        for path in [
            "/routing/targets/app",
            "/targets/../app",
            "/targets/%2e%2e/app",
            "/targets/app?signature=x",
            "/targets//app",
        ] {
            let response = request(&format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n")).await;
            assert!(
                response.starts_with(b"HTTP/1.1 404 Not Found\r\n"),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_writes_and_oversized_headers() {
        let response = request("PUT /targets/nested/app HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert!(response.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
        let huge = format!(
            "GET /targets/nested/app HTTP/1.1\r\nX: {}\r\n\r\n",
            "x".repeat(HEADER_LIMIT)
        );
        let response = request(&huge).await;
        assert!(response.starts_with(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    }
}
