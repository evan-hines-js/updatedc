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

/// The one-hot columns, taken from the planner's own list of verdicts rather than restated here.
///
/// [`GroupProgress::ALL`] is generated from the same list that declares the variants, so a verdict
/// cannot exist without a column here. This used to be a local array whose own comment conceded
/// that "what the compiler does not catch is a variant left out of this array": its groups rendered
/// all zeros and no hot column, which a dashboard reads as "no groups in any state".
const PROGRESS_STATES: [GroupProgress; GroupProgress::COUNT] = GroupProgress::ALL;

fn progress_label(progress: GroupProgress) -> &'static str {
    match progress {
        GroupProgress::Held => "held",
        GroupProgress::Rolling => "staging",
        // Frozen by a halt or a compliance block. Its own column: an operator watching "staging"
        // climb has no way to see that none of it can finish.
        GroupProgress::Blocked => "blocked",
        GroupProgress::Settled => "settled",
        // Its own state, never folded into "settled" or "staging": a group whose rollout ended in
        // durable rejection is neither done nor in flight, and counting it as either is what makes
        // a fleet dashboard say a bad release landed.
        GroupProgress::Failed => "failed",
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

/// Declare one series: its `# HELP` and `# TYPE`, written whether or not a sample follows.
fn declare(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// Render the exposition document. Pure — a function of reconciler state — so it is unit-tested as
/// text against constructed state, the same way status projection is tested.
///
/// Every series is DECLARED unconditionally and only its samples depend on state: before the first
/// successful pass the document is nothing but `# HELP`/`# TYPE` pairs and the failure counter, and
/// `updatec_generation` is declared with no samples until something is published. That is the
/// invariant docs/observability-design.md's testing section rests on — a name check passes against
/// an exposition that projected nothing, which is why the e2e reads sample VALUES. Skipping the
/// declarations instead would make a name check look like a real assertion on every scrape but the
/// pre-first-pass one, which is precisely the scrape the assertion exists to catch.
pub fn render(state: &MetricsState) -> String {
    let mut out = String::new();
    let snapshot = state.last.as_ref();
    declare(
        &mut out,
        "updatec_reconcile_failures_total",
        "counter",
        "Reconcile passes that failed since this process started.",
    );
    let _ = writeln!(
        out,
        "updatec_reconcile_failures_total {}",
        state.reconcile_failures_total
    );
    declare(
        &mut out,
        "updatec_reconcile_timestamp_seconds",
        "gauge",
        "When the last successful reconcile finished (unix seconds).",
    );
    if let Some(snapshot) = snapshot {
        let _ = writeln!(
            out,
            "updatec_reconcile_timestamp_seconds {}",
            snapshot.reconcile_timestamp_seconds
        );
    }
    declare(
        &mut out,
        "updatec_reconcile_duration_seconds",
        "gauge",
        "How long the last successful reconcile took.",
    );
    if let Some(snapshot) = snapshot {
        let _ = writeln!(
            out,
            "updatec_reconcile_duration_seconds {:.6}",
            snapshot.reconcile_duration_seconds
        );
    }
    declare(
        &mut out,
        "updatec_generation",
        "gauge",
        "The published generation, labeled per deployment name.",
    );
    if let Some((snapshot, generation)) = snapshot.and_then(|s| Some((s, s.generation?))) {
        for deployment in &snapshot.deployments {
            let _ = writeln!(
                out,
                "updatec_generation{{deployment=\"{}\"}} {generation}",
                escape(deployment)
            );
        }
    }
    let groups = snapshot.into_iter().flat_map(|snapshot| &snapshot.groups);
    declare(
        &mut out,
        "updatec_group_progress",
        "gauge",
        "One-hot projection of the planner verdict per group.",
    );
    for (group, (progress, _)) in groups.clone() {
        for state in PROGRESS_STATES {
            let value = u8::from(*progress == state);
            let _ = writeln!(
                out,
                "updatec_group_progress{{group=\"{}\",state=\"{}\"}} {value}",
                escape(group),
                progress_label(state)
            );
        }
    }
    declare(
        &mut out,
        "updatec_group_nodes",
        "gauge",
        "Nodes each group selects.",
    );
    for (group, (_, nodes)) in groups.clone() {
        let _ = writeln!(
            out,
            "updatec_group_nodes{{group=\"{}\"}} {}",
            escape(group),
            nodes.total
        );
    }
    declare(
        &mut out,
        "updatec_group_nodes_on_target",
        "gauge",
        "Nodes already handed the group's admitted deployment, as admission counts it.",
    );
    for (group, (_, nodes)) in groups {
        let _ = writeln!(
            out,
            "updatec_group_nodes_on_target{{group=\"{}\"}} {}",
            escape(group),
            nodes.on_target
        );
    }
    declare(
        &mut out,
        "updatec_reports_fresh",
        "gauge",
        "Node reports inside REPORT_FRESHNESS, as the admission gate counts them.",
    );
    if let Some(snapshot) = snapshot {
        let _ = writeln!(out, "updatec_reports_fresh {}", snapshot.reports_fresh);
    }
    declare(
        &mut out,
        "updatec_reports_stale",
        "gauge",
        "Nodes that have reported before but have no fresh authentic report.",
    );
    if let Some(snapshot) = snapshot {
        let _ = writeln!(out, "updatec_reports_stale {}", snapshot.reports_stale);
    }
    declare(
        &mut out,
        "updatec_quarantined_groups",
        "gauge",
        "Size of the quarantine set.",
    );
    if let Some(snapshot) = snapshot {
        let _ = writeln!(
            out,
            "updatec_quarantined_groups {}",
            snapshot.quarantined_groups
        );
    }
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
            "updatec_quarantined_groups 1",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// Every planner verdict must light exactly one column. A verdict missing from
    /// `PROGRESS_STATES` renders five zeros instead of erroring or vanishing, and an all-zero
    /// one-hot reads on a dashboard as "no groups in any state" — the fleet looks empty rather than
    /// unknown, which is the one wrong answer this series can give.
    #[test]
    fn every_group_progress_renders_exactly_one_hot_column() {
        // Over the planner's own list, which is complete by construction, so a new variant arrives
        // here without anyone remembering to add it.
        for progress in GroupProgress::ALL {
            let text = render(&MetricsState {
                reconcile_failures_total: 0,
                last: Some(FleetSnapshot {
                    reconcile_timestamp_seconds: 1_770_000_000,
                    reconcile_duration_seconds: 0.1,
                    generation: None,
                    deployments: Vec::new(),
                    groups: BTreeMap::from([(
                        "edge".to_string(),
                        (
                            progress,
                            GroupNodes {
                                total: 1,
                                on_target: 1,
                                fresh: 1,
                                observable: 1,
                                held: 0,
                                target: Some("id".into()),
                            },
                        ),
                    )]),
                    reports_fresh: 1,
                    reports_stale: 0,
                    quarantined_groups: 0,
                }),
            });
            let hot: Vec<&str> = text
                .lines()
                .filter(|line| line.starts_with("updatec_group_progress{"))
                .collect();
            assert_eq!(hot.len(), PROGRESS_STATES.len(), "{text}");
            assert_eq!(
                hot.iter().filter(|line| line.ends_with(" 1")).count(),
                1,
                "{progress:?} lights no column or more than one:\n{text}"
            );
            assert!(
                text.contains(&format!(
                    "updatec_group_progress{{group=\"edge\",state=\"{}\"}} 1",
                    progress_label(progress)
                )),
                "{text}"
            );
        }
    }

    /// Before the first successful pass there is nothing to project but the failure counter — the
    /// scrape must still answer, or "is the loop alive" is unanswerable exactly when it matters.
    /// Every other series is still DECLARED and carries no sample, which is the invariant
    /// docs/observability-design.md's testing section rests on: a search for a series NAME passes
    /// against a document that projected nothing, so an assertion must read values. A conditional
    /// declaration would make a name check pass on every scrape except this one.
    #[test]
    fn an_empty_state_declares_every_series_and_samples_only_the_failure_counter() {
        let text = render(&MetricsState {
            last: None,
            reconcile_failures_total: 3,
        });
        assert!(text.contains("updatec_reconcile_failures_total 3"));
        for series in [
            "updatec_reconcile_timestamp_seconds",
            "updatec_reconcile_duration_seconds",
            "updatec_generation",
            "updatec_group_progress",
            "updatec_group_nodes",
            "updatec_group_nodes_on_target",
            "updatec_reports_fresh",
            "updatec_reports_stale",
            "updatec_quarantined_groups",
        ] {
            assert!(
                text.contains(&format!("# TYPE {series} gauge")),
                "{series} is not declared in:\n{text}"
            );
        }
        // Declared, but nothing was projected: no line of this document is a sample except the
        // failure counter's.
        let samples: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        assert_eq!(
            samples,
            vec!["updatec_reconcile_failures_total 3"],
            "{text}"
        );
    }

    /// A published generation is the only thing `updatec_generation` samples: a pass that
    /// published nothing declares the series and emits no line, so an alert reading its value sees
    /// no series at all rather than a zero it would treat as a real generation.
    #[test]
    fn a_pass_that_published_nothing_declares_the_generation_series_with_no_sample() {
        let text = render(&MetricsState {
            reconcile_failures_total: 0,
            last: Some(FleetSnapshot {
                reconcile_timestamp_seconds: 1_770_000_000,
                reconcile_duration_seconds: 0.1,
                generation: None,
                deployments: vec!["app-v2".into()],
                groups: BTreeMap::new(),
                reports_fresh: 0,
                reports_stale: 0,
                quarantined_groups: 0,
            }),
        });
        assert!(text.contains("# TYPE updatec_generation gauge"), "{text}");
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("updatec_generation{")),
            "{text}"
        );
    }

    /// Label values travel inside double quotes, so the three escapes the exposition format
    /// defines must be applied.
    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
