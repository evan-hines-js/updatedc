use crate::*;
use std::collections::VecDeque;
use std::time::Instant;

/// One synthetic request outcome, kept only long enough to age out of [`LOAD_WINDOW`].
#[derive(Clone)]
pub(crate) struct LoadSample {
    pub(crate) at: Instant,
    pub(crate) ok: bool,
    pub(crate) latency_ms: u64,
}

/// The rolling record of synthetic-client outcomes the golden signals are derived from.
#[derive(Default)]
pub(crate) struct LoadWindow {
    pub(crate) samples: VecDeque<LoadSample>,
}

impl LoadWindow {
    pub(crate) fn record(&mut self, sample: LoadSample) {
        if let Some(cutoff) = sample.at.checked_sub(LOAD_WINDOW) {
            while self.samples.front().is_some_and(|old| old.at < cutoff) {
                self.samples.pop_front();
            }
        }
        self.samples.push_back(sample);
    }
}

/// The four golden signals plus the SLA line and error budget, as the panel renders them.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GoldenSignals {
    pub(crate) window_secs: u64,
    pub(crate) requests: usize,
    /// Sustained request rate over the window, requests/second.
    pub(crate) request_rate: f64,
    pub(crate) errors: usize,
    /// `None` when the window holds no requests: "no data", not a fabricated 0% error rate.
    pub(crate) error_rate: Option<f64>,
    /// `None` when the window holds no requests: with nothing measured the fleet has neither
    /// met nor missed its SLA, so rendering 100%/green would be a lie.
    pub(crate) availability: Option<f64>,
    pub(crate) latency_p50_ms: u64,
    pub(crate) latency_p95_ms: u64,
    pub(crate) ready_endpoints: usize,
    pub(crate) sla_target: f64,
    pub(crate) sla_met: bool,
    /// Percentage of the window's error budget still unspent (0 once the SLA is breached);
    /// `None` when the window holds no requests, so no budget has been earned or spent.
    pub(crate) error_budget_remaining: Option<f64>,
    /// True until the window has filled, so the panel can label early, understated rates.
    pub(crate) warming_up: bool,
}

/// The golden signals for the whole fleet plus a breakdown per set, so each set box can
/// render its own load balancer's health beside the fleet-wide SLA panel.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GoldenReport {
    pub(crate) fleet: GoldenSignals,
    pub(crate) sets: Vec<SetSignals>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetSignals {
    pub(crate) set: String,
    pub(crate) signals: GoldenSignals,
}

impl GoldenSignals {
    pub(crate) fn from_window(window: &LoadWindow, ready_endpoints: usize, now: Instant) -> Self {
        let requests = window.samples.len();
        let errors = window.samples.iter().filter(|sample| !sample.ok).count();
        // No requests in the window is "no data", not a perfect score: fabricating 100% would
        // render green and mint a full error budget the fleet never actually earned.
        let availability =
            (requests > 0).then(|| (requests - errors) as f64 / requests as f64 * 100.0);
        let error_rate = availability.map(|avail| 100.0 - avail);
        let mut latencies: Vec<u64> = window
            .samples
            .iter()
            .map(|sample| sample.latency_ms)
            .collect();
        latencies.sort_unstable();
        let percentile = |sorted: &[u64], p: f64| -> u64 {
            if sorted.is_empty() {
                return 0;
            }
            let rank = (p * (sorted.len() - 1) as f64).round() as usize;
            sorted[rank.min(sorted.len() - 1)]
        };
        // Span the window has actually covered, from the globally-*oldest* sample — the `min`,
        // not the deque front. For the fleet aggregate the front is merely set-0's oldest (the
        // per-set windows are concatenated, not merge-sorted), so keying off it would understate
        // the span and inflate the request rate; `min` is correct for every window.
        let span = window
            .samples
            .iter()
            .map(|sample| sample.at)
            .min()
            .map(|oldest| now.saturating_duration_since(oldest).as_secs_f64())
            .unwrap_or(0.0)
            .max(1.0);
        let allowed_error_rate = 100.0 - DEMO_SLA_TARGET;
        let error_budget_remaining = error_rate.map(|rate| {
            if allowed_error_rate <= 0.0 {
                0.0
            } else {
                ((allowed_error_rate - rate) / allowed_error_rate * 100.0).clamp(0.0, 100.0)
            }
        });
        GoldenSignals {
            window_secs: LOAD_WINDOW.as_secs(),
            requests,
            request_rate: requests as f64 / span,
            errors,
            error_rate,
            availability,
            latency_p50_ms: percentile(&latencies, 0.50),
            latency_p95_ms: percentile(&latencies, 0.95),
            ready_endpoints,
            sla_target: DEMO_SLA_TARGET,
            sla_met: availability.is_some_and(|avail| avail >= DEMO_SLA_TARGET),
            error_budget_remaining,
            warming_up: span < LOAD_WINDOW.as_secs_f64() - 1.0,
        }
    }
}
