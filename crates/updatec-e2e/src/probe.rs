//! The in-cluster load probe behind the zero-lost-requests assertion.
//!
//! `updatec-e2e load-probe <url> <interval_ms>` runs from this same binary — already in the node
//! image, like `alert-sink` — as a pod INSIDE the cluster, so every request rides the same
//! Service path production traffic does. That placement is the whole point: the previous probe
//! crossed the host↔cluster boundary through `kubectl port-forward`, whose own reconnect blips
//! are indistinguishable from dropped traffic, and the assertion had to absorb them with an
//! availability tolerance. A probe with no flaky hop in front of it can hold the tier to the
//! claim the product actually makes: ZERO failed requests across an in-place upgrade.
//!
//! The probe never stops on its own; the harness deletes the pod. Collection is race-free by
//! shape, not by coordination: every summary line is CUMULATIVE, so whichever line the harness
//! reads last covers the entire run up to that instant.

use std::io::Write;
use std::time::{Duration, Instant};

/// How often a cumulative summary line is emitted.
const SUMMARY_EVERY: Duration = Duration::from_millis(500);

/// Per-request budget. Generous against an in-cluster round trip; a response slower than this is
/// service lost from the caller's point of view and counts as a failure.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(800);

/// A health/version response is a few bytes. Use the shared streamed-body gate so a broken backend
/// cannot turn the permanent probe into an unbounded allocator before the request deadline fires.
const RESPONSE_BODY_LIMIT: usize = 8 * 1024;

/// One cumulative observation window, serialized as a single JSON line per emission — and parsed
/// back from the pod log by the harness ([`Summary::from_logs`]). ONE definition for the one wire
/// document, written and read: two mirrored structs let a field renamed on the writer alone still
/// compile, still serialize, and still parse, with the reader silently reading a default.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Summary {
    /// Requests attempted so far.
    pub total: u64,
    /// Requests that failed: transport error, timeout, non-2xx, or an empty body — a mangled
    /// response mid-re-exec is as lost as a refused connection.
    pub failed: u64,
    /// The longest observed gap between consecutive SUCCESSFUL responses, in milliseconds. Failed
    /// requests alone cannot see a stall that merely queues requests; this can, so the harness can
    /// bound blackout windows as well as hold failures to zero.
    pub max_gap_ms: u64,
    /// What the first failure looked like, for the harness's error message. Empty while none.
    pub first_failure: String,
}

impl Summary {
    /// Parse the LAST summary line out of a probe pod's log stream — cumulative lines make the
    /// last one authoritative for the whole run.
    pub(crate) fn from_logs(logs: &str) -> Option<Self> {
        logs.lines()
            .rev()
            .find_map(|line| serde_json::from_str(line.trim()).ok())
    }
}

/// Probe `url` every `interval_ms` forever, emitting a cumulative [`Summary`] line every
/// [`SUMMARY_EVERY`]. Requests are sequential — the measurement is "a client's request stream
/// across the upgrade", not a throughput benchmark — and the interval paces steady load.
pub(crate) async fn run(url: &str, interval_ms: u64) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = updated::http::network_endpoint(
        url,
        updated::http::EndpointTransport::HttpOrHttps,
        "load probe URL",
    )?;
    let client =
        updated::http::outbound_client(updated::http::OutboundDeadline::Total(REQUEST_TIMEOUT))?;
    let interval = Duration::from_millis(interval_ms.max(1));
    let mut total = 0u64;
    let mut failed = 0u64;
    let mut first_failure = String::new();
    let mut last_ok = Instant::now();
    let mut max_gap = Duration::ZERO;
    let mut last_summary = Instant::now();
    loop {
        let outcome = match client.get(endpoint.clone()).send().await {
            Ok(response) => {
                match updated::http::read_bounded(response, "load probe", RESPONSE_BODY_LIMIT).await
                {
                    Ok(body) => match std::str::from_utf8(&body) {
                        Ok(body) if !body.trim().is_empty() => Ok(()),
                        Ok(_) => Err("empty response body".to_string()),
                        Err(_) => Err("response body is not UTF-8".to_string()),
                    },
                    Err(error) => Err(error.to_string()),
                }
            }
            Err(error) => {
                Err(updated::http::redacted_reqwest_error("load probe", &error).to_string())
            }
        };
        total += 1;
        match outcome {
            Ok(()) => {
                max_gap = max_gap.max(last_ok.elapsed());
                last_ok = Instant::now();
            }
            Err(error) => {
                failed += 1;
                if first_failure.is_empty() {
                    first_failure = format!("request {total}: {error}");
                }
            }
        }
        if last_summary.elapsed() >= SUMMARY_EVERY {
            last_summary = Instant::now();
            let line = serde_json::to_string(&Summary {
                total,
                failed,
                // A stall that is STILL open must be visible before it ends, or a probe wedged
                // behind a dead front would keep reporting the last healthy gap.
                max_gap_ms: max_gap.max(last_ok.elapsed()).as_millis() as u64,
                first_failure: first_failure.clone(),
            })?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{line}")?;
            stdout.flush()?;
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The wire round-trips through the ONE definition both halves use — what the probe emits is
    /// what the harness parses — and the last cumulative line wins over everything before it, junk
    /// lines included.
    #[test]
    fn the_last_cumulative_summary_line_is_authoritative() {
        let emitted = Summary {
            total: 400,
            failed: 1,
            max_gap_ms: 900,
            first_failure: "request 37: status 503".into(),
        };
        let logs = format!(
            "{}\nstarting up noise\n{}\n",
            serde_json::to_string(&Summary {
                total: 10,
                failed: 0,
                max_gap_ms: 40,
                first_failure: String::new(),
            })
            .unwrap(),
            serde_json::to_string(&emitted).unwrap(),
        );
        assert_eq!(Summary::from_logs(&logs), Some(emitted));
        assert_eq!(Summary::from_logs("no summaries at all\n"), None);
    }
}
