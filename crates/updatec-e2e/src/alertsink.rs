//! The in-cluster webhook receiver the alerting assertion reads.
//!
//! `updatec` delivers one JSON document per condition transition to `UPDATED_ALERT_URL`
//! (`docs/alerting-design.md`). Asserting that end to end needs a real HTTP endpoint the
//! controller can reach from inside the cluster, and a DURABLE record of what arrived — the e2e
//! asserts on records, never on a log scrape. So this subcommand runs the receiver: every accepted
//! body is appended verbatim, one per line, to a file the assertion reads back with `kubectl exec`.
//!
//! It ships in the binary the e2e already builds into the node image rather than as a bespoke
//! image or a shell one-liner, so the receiver is the same artifact the rest of the run is.
//!
//! The request read below is hand-rolled rather than served through `updatec`'s axum for the same
//! reason: this binary is baked into every node image, and a test sink is not worth pulling an
//! HTTP server framework (and its tower/hyper tree) into that image to accept one POST whose exact
//! shape the controller's own delivery code fixes. The whole grammar it needs is `Content-Length`
//! and the header terminator, both pinned by the test below.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Where deliveries are recorded, and the port the receiver listens on. Both are read by
/// `Chaos::assert_halt_and_alert` through these constants, so the deployment manifest and the
/// assertion cannot disagree about where the record lives.
pub(super) const ALERT_RECORD: &str = "/tmp/alerts.jsonl";
pub(super) const ALERT_PORT: u16 = 8080;

/// The largest delivery body accepted. An alert document is a handful of short fields; anything
/// larger is not one, and a receiver that will read any length is a way to hang the test.
const MAX_BODY: usize = 64 * 1024;

/// How long one connection may hold the receiver, from accept to response. `MAX_BODY` bounds a
/// delivery's SIZE; this bounds its TIME, and the loop below needs both because it serves inline:
/// any peer that completes the handshake and then stops — a port scan, a probe that never closes,
/// a delivery `updatec` already abandoned at its own 10s `DELIVERY_TIMEOUT` whose FIN is delayed —
/// parks every later delivery behind it for as long as it keeps the socket open. The sink listens
/// on `0.0.0.0`, so the peer is not necessarily the controller the serialization below reasons
/// about. Generous against that 10s delivery deadline: a POST the controller has already given up
/// on is not one this sink has any reason to keep waiting for.
const SERVE_TIMEOUT: Duration = Duration::from_secs(15);

/// The pause after a failed `accept`, as in this workspace's other accept loops
/// (`updatec::gateway`, `updated_healthproxy::metrics`): a persistent error — fd exhaustion, a
/// torn-down interface — must cost a paced retry, not a tight spin, and must never end the loop.
/// Propagating it instead ended `run`, which exits the container; the Deployment restarts it, but
/// `ALERT_RECORD` lives in that container's filesystem, so the restart DISCARDS every delivery
/// recorded so far and drops the ones that arrive while it is down. The assertion then fails as a
/// missing alert — a diagnosis aimed at the controller's alerting path rather than at this sink.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Serve until killed, appending each POSTed body to `ALERT_RECORD` as one line.
pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("0.0.0.0", ALERT_PORT)).await?;
    println!("[alert-sink] recording deliveries to {ALERT_RECORD}");
    accept_forever(listener, PathBuf::from(ALERT_RECORD), SERVE_TIMEOUT).await;
    Ok(())
}

/// The accept loop itself, over an already-bound listener and an explicit deadline so the wedging
/// case is driven by the test below rather than only in a cluster.
async fn accept_forever(listener: TcpListener, record: PathBuf, deadline: Duration) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                println!("[alert-sink] accept failed: {error}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        // Serialized on purpose: deliveries are one in flight by construction (the sink drains its
        // queue one event at a time), and appending from one task keeps the record's lines whole.
        // Bounded because that construction describes the CONTROLLER, not every peer that can
        // reach this port.
        match tokio::time::timeout(deadline, serve(stream, &record)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => println!("[alert-sink] dropped a connection: {error}"),
            Err(_) => println!(
                "[alert-sink] abandoned a connection that sent no complete request within {}s",
                deadline.as_secs()
            ),
        }
    }
}

async fn serve(mut stream: TcpStream, record: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until the headers are complete, then until `Content-Length` bytes of body have arrived.
    // The controller sends one request per connection and waits for the response, so there is no
    // pipelining to account for.
    let (header_end, length) = loop {
        if let Some(end) = find_header_end(&buffer) {
            break (end, content_length(&buffer[..end])?);
        }
        if buffer.len() > MAX_BODY {
            return Err("alert headers exceeded the bound".into());
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err("connection closed before the request headers were complete".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    if length > MAX_BODY {
        return Err(format!("alert body of {length} bytes exceeds the bound").into());
    }
    while buffer.len() < header_end + length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err("connection closed before the request body was complete".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    append_record(record, &buffer[header_end..header_end + length]).await?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    Ok(())
}

/// Append one complete delivery through the workspace's sole managed-record opener.
///
/// The configured record path is writable state inside the sink container. Refusing a final
/// symlink keeps that authority on the named record instead of letting a planted path redirect
/// the controller's alert bodies into an unrelated file. Converting the already-validated
/// standard handle preserves that no-follow proof while allowing the socket task to await I/O.
async fn append_record(record: &Path, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut line = body.to_vec();
    line.push(b'\n');
    let file = foundation::file::open_append_file(record)?;
    let mut file = tokio::fs::File::from_std(file);
    file.write_all(&line).await?;
    file.flush().await?;
    file.sync_data().await?;
    Ok(())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length(headers: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
    let headers = std::str::from_utf8(headers)?;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return Ok(value.trim().parse()?);
        }
    }
    Err("alert delivery carried no content-length".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_is_located_by_the_headers_the_controller_sends() {
        let request =
            b"POST /alerts HTTP/1.1\r\nhost: alert-sink\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let end = find_header_end(request).expect("headers end at the blank line");
        assert_eq!(content_length(&request[..end]).unwrap(), 7);
        assert_eq!(&request[end..], b"{\"a\":1}");
    }

    #[tokio::test]
    async fn a_delivered_document_is_appended_to_the_record_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("alerts.jsonl");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let path = record.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve(stream, &path).await.unwrap();
        });
        let document =
            r#"{"resource":"UpdateGroupSet/fleet-set-00","condition":"DeploymentHalted"}"#;
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{port}/alerts"))
            .body(document.to_string())
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        server.await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&record).unwrap(),
            format!("{document}\n")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn alert_records_cannot_redirect_their_append_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        let record = dir.path().join("alerts.jsonl");
        std::fs::write(&outside, b"must remain ordinary state").unwrap();
        std::os::unix::fs::symlink(&outside, &record).unwrap();

        assert!(
            append_record(&record, br#"{"condition":"DeploymentHalted"}"#)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"must remain ordinary state"
        );
    }

    /// The receiver serves inline, so a peer that connects and then says nothing is the one thing
    /// that can silence it: without a deadline that connection holds the accept loop for as long
    /// as it keeps the socket open, every later transition is delivered to a socket nobody
    /// accepts, the record stays empty, and `assert_halt_and_alert` fails as "no alerts recorded"
    /// — pointing at the controller's alerting path rather than at this sink.
    #[tokio::test]
    async fn a_silent_peer_does_not_park_the_deliveries_behind_it() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("alerts.jsonl");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let path = record.clone();
        tokio::spawn(accept_forever(listener, path, Duration::from_millis(200)));
        // Accepted first, and held open for the rest of the test without sending a byte.
        let _silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let document =
            r#"{"resource":"UpdateGroupSet/fleet-set-00","condition":"DeploymentHalted"}"#;
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            reqwest::Client::new()
                .post(format!("http://127.0.0.1:{port}/alerts"))
                .body(document.to_string())
                .send(),
        )
        .await
        .expect("a delivery behind a silent peer never got served")
        .unwrap();
        assert!(response.status().is_success());
        // `serve` writes and flushes the record before answering, so a successful response means
        // the line is already durable.
        assert_eq!(
            std::fs::read_to_string(&record).unwrap(),
            format!("{document}\n")
        );
    }
}
