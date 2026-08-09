//! The healthproxy metrics exposition (docs/observability-design.md).
//!
//! Prometheus text exposition, hand-rolled like `updatec`'s: no metrics framework, four series,
//! each a projection of what the reconcile loop just programmed. Served on a dedicated
//! plain-HTTP listener (`HEALTHPROXY_METRICS_ADDRESS`, default off) that answers `GET /metrics`
//! and nothing else. The HTTP framing is deliberately minimal — one bounded read, one response,
//! close — because this crate carries no HTTP server dependency and a scrape needs nothing more.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

/// What the reconcile loop last programmed, plus the one counter that survives cycles.
#[derive(Debug, Default)]
pub struct ProxyMetrics {
    /// Backends programmed ready in the last reconcile.
    pub backends_up: usize,
    /// Backends programmed drained in the last reconcile.
    pub backends_drained: usize,
    /// Drains caused by report STALENESS — the number that turns a silent freshness failure into
    /// a visible one. Incremented on the drain transition, not per cycle.
    pub reports_stale_total: u64,
    /// When the last reconcile finished, seconds since the Unix epoch. Zero until the first.
    pub reconcile_timestamp_seconds: u64,
    /// When a USABLE endpoint projection from the control plane was last observed, seconds since
    /// the Unix epoch — a document that arrived but does not decode is not an observation, or this
    /// series would read "current" while every cordon was being released. Zero until the first. The projection fails open — once it falls further behind than
    /// `LastKnownGood::STALENESS`, every cordon has been released and health alone governs — so
    /// this is what makes a silently lost cordon alertable, the mirror of what
    /// `reports_stale_total` does for a silently aged-out report.
    pub endpoints_timestamp_seconds: u64,
}

pub type Shared = Arc<Mutex<ProxyMetrics>>;

/// Render the exposition document. Pure, so it is unit-tested as text.
pub fn render(metrics: &ProxyMetrics) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP healthproxy_backends Backends by programmed state, per the last reconcile."
    );
    let _ = writeln!(out, "# TYPE healthproxy_backends gauge");
    let _ = writeln!(
        out,
        "healthproxy_backends{{state=\"up\"}} {}",
        metrics.backends_up
    );
    let _ = writeln!(
        out,
        "healthproxy_backends{{state=\"drained\"}} {}",
        metrics.backends_drained
    );
    let _ = writeln!(
        out,
        "# HELP healthproxy_reports_stale_total Drains caused by report staleness."
    );
    let _ = writeln!(out, "# TYPE healthproxy_reports_stale_total counter");
    let _ = writeln!(
        out,
        "healthproxy_reports_stale_total {}",
        metrics.reports_stale_total
    );
    let _ = writeln!(out, "# HELP healthproxy_reconcile_timestamp_seconds When the last reconcile finished (unix seconds).");
    let _ = writeln!(out, "# TYPE healthproxy_reconcile_timestamp_seconds gauge");
    let _ = writeln!(
        out,
        "healthproxy_reconcile_timestamp_seconds {}",
        metrics.reconcile_timestamp_seconds
    );
    let _ = writeln!(out, "# HELP healthproxy_endpoints_timestamp_seconds When the control plane's endpoint projection was last observed (unix seconds).");
    let _ = writeln!(out, "# TYPE healthproxy_endpoints_timestamp_seconds gauge");
    let _ = writeln!(
        out,
        "healthproxy_endpoints_timestamp_seconds {}",
        metrics.endpoints_timestamp_seconds
    );
    out
}

/// The most of a scrape request this listener will read: a `GET /metrics HTTP/1.1` line plus a few
/// headers. Anything longer is not a scrape.
const REQUEST_BYTES_LIMIT: usize = 4096;

/// Serve `GET /metrics` forever on `address`. Any other request — and any request that does not
/// finish arriving within a short deadline — is answered 404 (or dropped) and the connection
/// closed; the listener holds no state and serves nothing else.
pub async fn serve(address: std::net::SocketAddr, metrics: Shared) -> Result<(), std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(address).await?;
    eprintln!("healthproxy: metrics listener serving /metrics on {address}");
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            // A persistent accept error (fd exhaustion, a torn-down interface) must cost a paced
            // retry, not a spin that pegs a core.
            Err(error) => {
                eprintln!("healthproxy: metrics accept failed: {error}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let request = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut buffer = vec![0u8; REQUEST_BYTES_LIMIT];
                let mut read = 0usize;
                loop {
                    let n = socket.read(&mut buffer[read..]).await.ok()?;
                    if n == 0 {
                        return None;
                    }
                    read += n;
                    if buffer[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                        return Some(buffer[..read].to_vec());
                    }
                    if read == buffer.len() {
                        return None;
                    }
                }
            })
            .await
            .ok()
            .flatten();
            // The request-target may carry a query string (some scrapers append one); the path is
            // what names the resource.
            let is_scrape = request.as_deref().is_some_and(|head| {
                head.strip_prefix(b"GET /metrics")
                    .and_then(|rest| rest.first())
                    .is_some_and(|byte| matches!(byte, b' ' | b'?' | b'\r'))
            });
            let response = if is_scrape {
                let body = render(&metrics.lock().expect("metrics lock"));
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain; version=0.0.4\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into()
            };
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exposition_projects_the_last_reconcile() {
        let text = render(&ProxyMetrics {
            backends_up: 4,
            backends_drained: 2,
            reports_stale_total: 7,
            reconcile_timestamp_seconds: 1_770_000_000,
            endpoints_timestamp_seconds: 1_769_999_940,
        });
        for expected in [
            "healthproxy_backends{state=\"up\"} 4",
            "healthproxy_backends{state=\"drained\"} 2",
            "# TYPE healthproxy_reports_stale_total counter",
            "healthproxy_reports_stale_total 7",
            "healthproxy_reconcile_timestamp_seconds 1770000000",
            "# TYPE healthproxy_endpoints_timestamp_seconds gauge",
            "healthproxy_endpoints_timestamp_seconds 1769999940",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// The listener end to end: a scrape gets the document, anything else a 404.
    #[tokio::test]
    async fn the_listener_answers_a_scrape_and_nothing_else() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let metrics: Shared = Arc::default();
        metrics.lock().unwrap().backends_up = 3;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let served = metrics.clone();
        let bind: std::net::SocketAddr = address.parse().unwrap();
        tokio::spawn(async move {
            serve(bind, served).await.unwrap();
        });
        // The listener may take a moment to bind after the probe socket freed the port.
        let mut scrape = None;
        for _ in 0..50 {
            if let Ok(socket) = tokio::net::TcpStream::connect(&address).await {
                scrape = Some(socket);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut socket = scrape.expect("metrics listener never came up");
        socket
            .write_all(b"GET /metrics HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.contains("healthproxy_backends{state=\"up\"} 3"));

        let mut socket = tokio::net::TcpStream::connect(&address).await.unwrap();
        socket
            .write_all(b"GET /other HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }
}
