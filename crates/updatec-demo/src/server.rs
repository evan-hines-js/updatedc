use crate::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Cap on a single request (headers + body). Generous for this UI's small JSON payloads while
/// bounding memory and any slow-drip client.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// A whole request must arrive within this window, so a stalled or slow-loris client drops
/// instead of pinning its handler task.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Read a full HTTP/1.1 request: keep reading until the header terminator *and* the entire
/// `Content-Length` body have arrived, so a request split across TCP segments (routine for
/// `fetch`/`reqwest`) is never parsed truncated — the bug that intermittently 400'd POSTs.
async fn read_request(stream: &mut TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let read = tokio::time::timeout(REQUEST_READ_TIMEOUT, stream.read(&mut chunk)).await??;
        if read == 0 {
            break; // peer closed
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() >= MAX_REQUEST_BYTES {
            buf.truncate(MAX_REQUEST_BYTES);
            break;
        }
        if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let declared = content_length(&buf[..header_end]);
            if buf.len() - (header_end + 4) >= declared {
                break; // full headers + declared body in hand
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The `Content-Length` of a request from its raw header block (case-insensitive); `0` when
/// absent or unparseable, which is correct for the bodyless GETs this server mostly serves.
fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0)
}

/// A JSON error response in the `(status, content_type, body)` shape every route arm returns —
/// `{"error": "<message>"}` with `application/json`. Collapses the ~10 identical error arms below.
fn json_error(status: &'static str, error: impl std::fmt::Display) -> (&'static str, &'static str, String) {
    (
        status,
        "application/json",
        serde_json::json!({ "error": error.to_string() }).to_string(),
    )
}

pub(crate) async fn serve(mut stream: TcpStream, demo: Demo) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_request(&mut stream).await?;
    let request = request.as_str();
    let mut words = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = words.next().unwrap_or_default();
    let path = words.next().unwrap_or_default();
    let (status, content_type, body) = match (method, path) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", demo.page()),
        ("GET", "/state") => match demo.version().await {
            Ok(version) => (
                "200 OK",
                "application/json",
                serde_json::json!({
                    "version": version.trim(),
                    "color": if version.trim() == "2.0.0" { "green" } else { "red" }
                })
                .to_string(),
            ),
            Err(error) => json_error("503 Service Unavailable", error),
        },
        ("GET", "/fleet") => match demo.fleet_for_ui().await {
            Ok(nodes) => (
                "200 OK",
                "application/json",
                serde_json::to_string(&nodes)?,
            ),
            Err(error) => json_error("503 Service Unavailable", error),
        },
        ("GET", "/groups") => match demo.groups().await {
            Ok(groups) => (
                "200 OK",
                "application/json",
                serde_json::to_string(&groups)?,
            ),
            Err(error) => json_error("503 Service Unavailable", error),
        },
        ("GET", "/sets") => match demo.sets().await {
            Ok(sets) => ("200 OK", "application/json", serde_json::to_string(&sets)?),
            Err(error) => json_error("503 Service Unavailable", error),
        },
        ("POST", action) if action.starts_with("/calendar/add") => {
            let set = query_value(action, "set").unwrap_or_else(|| DEMO_FLEET_SET.to_string());
            match query_value(action, "date") {
                Some(date) => match demo.add_calendar_date(&set, &date).await {
                    Ok(()) => (
                        "202 Accepted",
                        "application/json",
                        serde_json::json!({"status": format!("added {date} to {set}")}).to_string(),
                    ),
                    Err(error) => json_error("400 Bad Request", error),
                },
                None => json_error("400 Bad Request", "date query parameter is required"),
            }
        }
        ("POST", action) if action.starts_with("/calendar/clear") => {
            let set = query_value(action, "set").unwrap_or_else(|| DEMO_FLEET_SET.to_string());
            match demo.clear_calendar(&set).await {
                Ok(()) => (
                    "202 Accepted",
                    "application/json",
                    serde_json::json!({"status": format!("cleared {set}")}).to_string(),
                ),
                Err(error) => json_error("500 Internal Server Error", error),
            }
        }
        ("GET", "/chaos") => (
            "200 OK",
            "application/json",
            serde_json::to_string(&*demo.chaos.lock().await)?,
        ),
        ("GET", "/golden") => (
            "200 OK",
            "application/json",
            serde_json::to_string(&demo.golden())?,
        ),
        ("POST", action) if action.starts_with("/chaos/start") => {
            let seed = query_value(action, "seed")
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(random_seed);
            let loops = match query_value(action, "loops").as_deref() {
                Some("forever") | None => None,
                Some(value) => Some(value.parse::<usize>().unwrap_or(1).max(1)),
            };
            match demo.start_chaos(seed, loops).await {
                Ok(()) => (
                    "202 Accepted",
                    "application/json",
                    serde_json::json!({"status":"seeded fleet chaos started", "seed":seed})
                        .to_string(),
                ),
                Err(error) => json_error("409 Conflict", error),
            }
        }
        ("POST", "/update") => match request_body(request)
            .and_then(|body| {
                serde_json::from_str::<ReleaseRequest>(body).map_err(|error| error.to_string())
            })
        {
            Ok(release) => match demo.apply(&release).await {
                Ok(()) => (
                    "202 Accepted",
                    "application/json",
                    serde_json::json!({"status": "submitted to Kubernetes; waiting for the operator"})
                        .to_string(),
                ),
                Err(error) => json_error("500 Internal Server Error", error),
            },
            Err(error) => json_error("400 Bad Request", error),
        },
        ("POST", "/magnolia/upgrade") => match demo.upgrade_magnolia_manual().await {
            Ok(()) => (
                "202 Accepted",
                "application/json",
                serde_json::json!({"status": "manual Magnolia upgrade to v2 requested"})
                    .to_string(),
            ),
            Err(error) => json_error("500 Internal Server Error", error),
        },
        ("GET", "/healthz") => ("200 OK", "text/plain", "ok".into()),
        _ => ("404 Not Found", "text/plain", "not found".into()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

pub(crate) fn request_body(request: &str) -> Result<&str, String> {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .ok_or_else(|| "request body is missing".into())
}

pub(crate) fn query_value(path: &str, name: &str) -> Option<String> {
    path.split_once('?')?.1.split('&').find_map(|field| {
        let (key, value) = field.split_once('=')?;
        (key == name).then(|| percent_decode(value))
    })
}

/// Percent-decode an `application/x-www-form-urlencoded` query value — `%XX` byte escapes and
/// `+` as space, lossily for any non-UTF-8 result. Query values feed straight into Kubernetes
/// patches (a calendar `date`, a `set` name), so an encoded value must be decoded before use.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    // Not a valid escape — keep the literal '%' and continue.
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
