//! The in-cluster webhook receiver the alerting assertion reads.
//!
//! `updatec` delivers one JSON document per condition transition to `UPDATED_ALERT_URL`
//! ([`docs/alerting-design.md`]). Asserting that end to end needs a real HTTP endpoint the
//! controller can reach from inside the cluster, and a DURABLE record of what arrived — the e2e
//! asserts on records, never on a log scrape. So this subcommand runs the receiver: every accepted
//! body is appended verbatim, one per line, to a file the assertion reads back with `kubectl exec`.
//!
//! It ships in the binary the e2e already builds into the node image rather than as a bespoke
//! image or a shell one-liner, so the receiver is the same artifact the rest of the run is.

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Where deliveries are recorded, and the port the receiver listens on. Both are read by
/// [`crate::assert_regression_halt_alerted`] through these constants, so the deployment manifest
/// and the assertion cannot disagree about where the record lives.
pub(super) const ALERT_RECORD: &str = "/tmp/alerts.jsonl";
pub(super) const ALERT_PORT: u16 = 8080;

/// The largest delivery body accepted. An alert document is a handful of short fields; anything
/// larger is not one, and a receiver that will read any length is a way to hang the test.
const MAX_BODY: usize = 64 * 1024;

/// Serve until killed, appending each POSTed body to `ALERT_RECORD` as one line.
pub(crate) async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("0.0.0.0", ALERT_PORT)).await?;
    println!("[alert-sink] recording deliveries to {ALERT_RECORD}");
    loop {
        let (stream, _) = listener.accept().await?;
        // Serialized on purpose: deliveries are one in flight by construction (the sink drains its
        // queue one event at a time), and appending from one task keeps the record's lines whole.
        if let Err(error) = serve(stream, Path::new(ALERT_RECORD)).await {
            println!("[alert-sink] dropped a connection: {error}");
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
    let body = &buffer[header_end..header_end + length];
    let mut line = body.to_vec();
    line.push(b'\n');
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(record)
        .await?;
    file.write_all(&line).await?;
    file.flush().await?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
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
}
