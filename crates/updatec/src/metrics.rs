//! Operator observability: the `updatec` metrics exposition (docs/observability-design.md).
//!
//! Prometheus text exposition, hand-rolled. No metrics framework, no registry crate: the format is
//! a stable, line-oriented text grammar, and the set below is small enough that the binary formats
//! its own gauge lines from the state the reconcile loop already owns at scrape time. Every series
//! is a projection of state `reconcile_once` already computes — this module creates no new signal.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use crate::rollout::{GroupNodes, GroupProgress};

/// What one reconcile pass leaves behind for the scrape to project. Built by `reconcile_once` from
/// the same plan it publishes, so the scrape can never disagree with the CRD statuses.
#[derive(Debug)]
pub struct FleetSnapshot {
    /// When the pass finished, seconds since the Unix epoch.
    pub reconcile_timestamp_seconds: u64,
    /// How long the pass took.
    pub reconcile_duration_seconds: f64,
    /// The published TUF generation, when one exists.
    pub generation: Option<u64>,
    /// Deployment names published this generation (each group's admitted current plus the
    /// repository default), labels for `updatec_generation`.
    pub deployments: Vec<String>,
    /// Each planned group's verdict and node accounting, straight from the planner.
    pub groups: BTreeMap<String, (GroupProgress, GroupNodes)>,
    /// Agents with an authentic report inside `REPORT_FRESHNESS` — the same staleness the
    /// admission gate applies.
    pub reports_fresh: usize,
    /// Agents that have reported before (pinned key, at least one stored envelope) but have no
    /// fresh authentic report now. A never-reported agent is unobserved, not stale.
    pub reports_stale: usize,
    /// Size of the quarantine set this pass.
    pub quarantined_groups: usize,
    /// Nodes reporting under each report schema, from the verifications the pass already performed.
    /// The compatibility window admits older reports with newer fields at their fail-safe default,
    /// so the population below the current schema is exactly the population whose evidence is
    /// degraded — and the only in-system answer to "does any supported fleet still run the older
    /// agent", which is the precondition for raising the floor.
    pub report_schemas: BTreeMap<u32, usize>,
}

/// The state the metrics listener reads: the latest snapshot, plus the failure counter that must
/// survive failed passes (a failed pass produces no snapshot, which is exactly when the counter
/// matters).
#[derive(Debug, Default)]
pub struct MetricsState {
    pub last: Option<FleetSnapshot>,
    pub reconcile_failures_total: u64,
}

pub type SharedMetrics = Arc<std::sync::RwLock<MetricsState>>;

/// The one-hot label set, spelled once: the renderer emits exactly these states and
/// `progress_label` maps into them, so the two cannot drift into a label the other never uses.
const PROGRESS_STATES: [&str; 4] = ["staging", "held", "settled", "unobservable"];

fn progress_label(progress: GroupProgress) -> &'static str {
    match progress {
        GroupProgress::Held => "held",
        GroupProgress::Rolling => "staging",
        GroupProgress::Settled => "settled",
        GroupProgress::Unobservable => "unobservable",
    }
}

/// Escape a label value per the exposition format: backslash, double quote, newline.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Render the exposition document. Pure — a function of reconciler state — so it is unit-tested as
/// text against constructed state, the same way status projection is tested.
pub fn render(state: &MetricsState) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP updatec_reconcile_failures_total Reconcile passes that failed since this process started."
    );
    let _ = writeln!(out, "# TYPE updatec_reconcile_failures_total counter");
    let _ = writeln!(
        out,
        "updatec_reconcile_failures_total {}",
        state.reconcile_failures_total
    );
    let Some(snapshot) = &state.last else {
        return out;
    };
    let _ = writeln!(out, "# HELP updatec_reconcile_timestamp_seconds When the last successful reconcile finished (unix seconds).");
    let _ = writeln!(out, "# TYPE updatec_reconcile_timestamp_seconds gauge");
    let _ = writeln!(
        out,
        "updatec_reconcile_timestamp_seconds {}",
        snapshot.reconcile_timestamp_seconds
    );
    let _ = writeln!(
        out,
        "# HELP updatec_reconcile_duration_seconds How long the last successful reconcile took."
    );
    let _ = writeln!(out, "# TYPE updatec_reconcile_duration_seconds gauge");
    let _ = writeln!(
        out,
        "updatec_reconcile_duration_seconds {:.6}",
        snapshot.reconcile_duration_seconds
    );
    if let Some(generation) = snapshot.generation {
        let _ = writeln!(
            out,
            "# HELP updatec_generation The published generation, labeled per deployment name."
        );
        let _ = writeln!(out, "# TYPE updatec_generation gauge");
        for deployment in &snapshot.deployments {
            let _ = writeln!(
                out,
                "updatec_generation{{deployment=\"{}\"}} {generation}",
                escape(deployment)
            );
        }
    }
    let _ = writeln!(
        out,
        "# HELP updatec_group_progress One-hot projection of the planner verdict per group."
    );
    let _ = writeln!(out, "# TYPE updatec_group_progress gauge");
    for (group, (progress, _)) in &snapshot.groups {
        for state in PROGRESS_STATES {
            let value = u8::from(progress_label(*progress) == state);
            let _ = writeln!(
                out,
                "updatec_group_progress{{group=\"{}\",state=\"{state}\"}} {value}",
                escape(group)
            );
        }
    }
    let _ = writeln!(out, "# HELP updatec_group_nodes Nodes each group selects.");
    let _ = writeln!(out, "# TYPE updatec_group_nodes gauge");
    for (group, (_, nodes)) in &snapshot.groups {
        let _ = writeln!(
            out,
            "updatec_group_nodes{{group=\"{}\"}} {}",
            escape(group),
            nodes.total
        );
    }
    let _ = writeln!(out, "# HELP updatec_group_nodes_on_target Nodes already handed the group's admitted deployment, as admission counts it.");
    let _ = writeln!(out, "# TYPE updatec_group_nodes_on_target gauge");
    for (group, (_, nodes)) in &snapshot.groups {
        let _ = writeln!(
            out,
            "updatec_group_nodes_on_target{{group=\"{}\"}} {}",
            escape(group),
            nodes.on_target
        );
    }
    let _ = writeln!(out, "# HELP updatec_reports_fresh Node reports inside REPORT_FRESHNESS, as the admission gate counts them.");
    let _ = writeln!(out, "# TYPE updatec_reports_fresh gauge");
    let _ = writeln!(out, "updatec_reports_fresh {}", snapshot.reports_fresh);
    let _ = writeln!(out, "# HELP updatec_reports_stale Nodes that have reported before but have no fresh authentic report.");
    let _ = writeln!(out, "# TYPE updatec_reports_stale gauge");
    let _ = writeln!(out, "updatec_reports_stale {}", snapshot.reports_stale);
    let _ = writeln!(out, "# HELP updatec_report_schema Nodes with a fresh authentic report, by the report schema they wrote.");
    let _ = writeln!(out, "# TYPE updatec_report_schema gauge");
    for (schema, nodes) in &snapshot.report_schemas {
        let _ = writeln!(out, "updatec_report_schema{{schema=\"{schema}\"}} {nodes}");
    }
    let _ = writeln!(
        out,
        "# HELP updatec_quarantined_groups Size of the quarantine set."
    );
    let _ = writeln!(out, "# TYPE updatec_quarantined_groups gauge");
    let _ = writeln!(
        out,
        "updatec_quarantined_groups {}",
        snapshot.quarantined_groups
    );
    out
}

/// Serve `GET /metrics` on a dedicated plain-HTTP listener. Cluster-internal, read-only, serves
/// nothing else — everything but `/metrics` is a 404.
pub async fn serve(
    address: std::net::SocketAddr,
    metrics: SharedMetrics,
) -> Result<(), std::io::Error> {
    use axum::routing::get;
    let app = axum::Router::new().route(
        "/metrics",
        get(move || {
            let metrics = metrics.clone();
            async move {
                let body = render(&metrics.read().expect("metrics lock"));
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "metrics listener serving /metrics");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exposition is a pure function of reconciler state: assert it as text against
    /// constructed state, the way status projection is tested.
    #[test]
    fn the_exposition_projects_a_settled_fleet() {
        let state = MetricsState {
            reconcile_failures_total: 2,
            last: Some(FleetSnapshot {
                reconcile_timestamp_seconds: 1_770_000_000,
                reconcile_duration_seconds: 0.25,
                generation: Some(41),
                deployments: vec!["app-v2".into(), "default".into()],
                groups: BTreeMap::from([
                    (
                        "edge".to_string(),
                        (
                            GroupProgress::Settled,
                            GroupNodes {
                                total: 3,
                                on_target: 3,
                                fresh: 3,
                                observable: 3,
                                held: 0,
                                target: Some("id".into()),
                            },
                        ),
                    ),
                    (
                        "core".to_string(),
                        (
                            GroupProgress::Rolling,
                            GroupNodes {
                                total: 5,
                                on_target: 2,
                                fresh: 4,
                                observable: 5,
                                held: 1,
                                target: Some("id2".into()),
                            },
                        ),
                    ),
                ]),
                reports_fresh: 7,
                reports_stale: 1,
                quarantined_groups: 1,
                report_schemas: BTreeMap::from([(5, 2), (6, 5)]),
            }),
        };
        let text = render(&state);
        for expected in [
            "# TYPE updatec_reconcile_failures_total counter",
            "updatec_reconcile_failures_total 2",
            "updatec_reconcile_timestamp_seconds 1770000000",
            "updatec_reconcile_duration_seconds 0.250000",
            "updatec_generation{deployment=\"app-v2\"} 41",
            "updatec_generation{deployment=\"default\"} 41",
            "updatec_group_progress{group=\"edge\",state=\"settled\"} 1",
            "updatec_group_progress{group=\"edge\",state=\"staging\"} 0",
            "updatec_group_progress{group=\"core\",state=\"staging\"} 1",
            "updatec_group_nodes{group=\"core\"} 5",
            "updatec_group_nodes_on_target{group=\"core\"} 2",
            "updatec_reports_fresh 7",
            "updatec_reports_stale 1",
            // The population still writing an older report schema, which is the population whose
            // rollbacks mint no regression evidence — invisible in every other series.
            "updatec_report_schema{schema=\"5\"} 2",
            "updatec_report_schema{schema=\"6\"} 5",
            "updatec_quarantined_groups 1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// Before the first successful pass there is nothing to project but the failure counter — the
    /// scrape must still answer, or "is the loop alive" is unanswerable exactly when it matters.
    #[test]
    fn an_empty_state_still_exposes_the_failure_counter() {
        let text = render(&MetricsState {
            last: None,
            reconcile_failures_total: 3,
        });
        assert!(text.contains("updatec_reconcile_failures_total 3"));
        assert!(!text.contains("updatec_reconcile_timestamp_seconds"));
    }

    /// Label values travel inside double quotes, so the three escapes the exposition format
    /// defines must be applied.
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
