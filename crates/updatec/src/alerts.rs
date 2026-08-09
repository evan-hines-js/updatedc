//! Alerting on stuck state: conditions and one webhook (docs/alerting-design.md).
//!
//! Alerts are projections of planner verdicts, nothing else. The reconcile loop already computes,
//! every pass, the exact conditions worth waking someone for; this module gives those conditions
//! two outputs — a status condition on the owning resource and one webhook POST per condition
//! TRANSITION — and adds no new detection logic. Conditions are the source of truth; the webhook
//! is only a delivery of their transitions, so a dropped webhook loses a notification, never a
//! fact.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::ResourceCondition;

const ROLLOUT_STUCK: &str = "RolloutStuck";
const REPORTS_STALE: &str = "ReportsStale";
const DEPLOYMENT_HALTED: &str = "DeploymentHalted";
pub const RECONCILE_FAILING: &str = "ReconcileFailing";

/// The default for `UpdateGroupSet.spec.stuckAfterSeconds`: an hour of staging with no node newly
/// settled before `RolloutStuck` rises.
pub const DEFAULT_STUCK_AFTER_SECONDS: u64 = 3600;

/// When rollout progress last advanced, per group — the one piece of memory `RolloutStuck` needs,
/// because a settled-node count says where a rollout is, never how long it has sat there.
///
/// Held in the controller's memory, not durably: a leader change or restart restarts the stuck
/// clock, so a genuinely wedged rollout re-raises the condition one `stuckAfterSeconds` later
/// rather than never. That is the fail direction a notification can afford; durable state for an
/// alert timer would be state the planner does not need.
#[derive(Debug, Default)]
pub struct ProgressTracker {
    entries: HashMap<String, ProgressMark>,
}

#[derive(Debug)]
struct ProgressMark {
    /// The admitted deployment identity progress is being tracked toward.
    target: Option<String>,
    /// Nodes already handed that identity, as the admission logic counts them.
    on_target: usize,
    /// When either of the above last changed — the instant progress last advanced.
    since: chrono::DateTime<chrono::Utc>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold in this pass's observation of `group` and return the instant its rollout last made
    /// progress: a changed target (a fresh admission is progress) or a grown on-target count
    /// resets the clock; anything else leaves it running. A shrunk count (a retarget, relabelled
    /// nodes) also resets — a rollout whose shape just changed is not "stuck since an hour ago".
    pub fn observe(
        &mut self,
        group: &str,
        target: Option<String>,
        on_target: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> chrono::DateTime<chrono::Utc> {
        match self.entries.get_mut(group) {
            Some(mark) if mark.target == target && mark.on_target == on_target => mark.since,
            Some(mark) => {
                mark.target = target;
                mark.on_target = on_target;
                mark.since = now;
                now
            }
            None => {
                self.entries.insert(
                    group.to_string(),
                    ProgressMark {
                        target,
                        on_target,
                        since: now,
                    },
                );
                now
            }
        }
    }

    /// Forget groups that no longer exist, so a deleted group's mark does not linger forever.
    pub fn retain<F: Fn(&str) -> bool>(&mut self, keep: F) {
        self.entries.retain(|name, _| keep(name));
    }
}

fn condition(
    condition_type: &str,
    active: bool,
    generation: Option<i64>,
    reason: &str,
    message: String,
    now: &chrono::DateTime<chrono::Utc>,
) -> ResourceCondition {
    ResourceCondition {
        condition_type: condition_type.into(),
        status: if active { "True" } else { "False" }.into(),
        reason: reason.into(),
        message,
        observed_generation: generation,
        last_transition_time: now.to_rfc3339(),
    }
}

/// `RolloutStuck` on an `UpdateGroup`: it has been staging with no node newly settled for longer
/// than its governing set's `stuckAfterSeconds`.
pub fn rollout_stuck(
    generation: Option<i64>,
    staging: bool,
    progressed_at: chrono::DateTime<chrono::Utc>,
    stuck_after_seconds: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> ResourceCondition {
    let stalled = now.signed_duration_since(progressed_at).num_seconds();
    let stuck = staging && stalled >= stuck_after_seconds.min(i64::MAX as u64) as i64;
    let (reason, message) = if stuck {
        (
            "NoNewSettledNode",
            format!("This group has been staging for {stalled}s with no node newly settled (stuckAfterSeconds: {stuck_after_seconds})."),
        )
    } else if staging {
        (
            "Progressing",
            "This group's rollout is staging and still making progress.".into(),
        )
    } else {
        ("NotStaging", "No rollout is staging.".into())
    };
    condition(ROLLOUT_STUCK, stuck, generation, reason, message, &now)
}

/// `ReportsStale` on an `UpdateGroup`: fewer than the group's admission quorum of nodes have fresh
/// reports. The quorum is what admission itself needs: a group may afford `maxUnavailable` silent
/// nodes, so the condition rises exactly when staleness alone exhausts that budget —
/// `REPORT_FRESHNESS` is the one staleness definition and it is already applied upstream, where
/// `fresh` was counted.
///
/// `observable` counts only nodes that have ALREADY reported at least once (see
/// [`crate::rollout::GroupNodes::observable`]), so this says "nodes stopped reporting", never
/// "nodes have not started yet": a keyed node is observable to the apiserver an enrollment before
/// it can possibly upload anything, and counting those made a mass enrollment or a scale-out
/// larger than `maxUnavailable` page and then resolve itself. It is controller MEMORY, not a
/// re-read of the store, which is what keeps `observable > 0` from being the very thing an
/// unreadable telemetry store takes away — clearing this condition exactly when the fleet goes
/// dark.
pub fn reports_stale(
    generation: Option<i64>,
    fresh: usize,
    observable: usize,
    max_unavailable: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> ResourceCondition {
    // Strictly MORE stale than the budget: `maxUnavailable` nodes being briefly unaccounted for is
    // the ordinary shape of a staged rollout (the node rebooting into the update it was just
    // handed reports nothing for longer than the freshness window), and an alert that fires on
    // every healthy rollout is an alert nobody reads. Only staleness past what admission tolerates
    // is news.
    let stale = observable.saturating_sub(fresh);
    let active = observable > 0 && stale > max_unavailable.max(1);
    let (reason, message) = if active {
        (
            "BelowQuorum",
            format!(
                "{fresh} of {observable} observable nodes have fresh reports; {stale} stale exceeds the group's maxUnavailable ({max_unavailable})."
            ),
        )
    } else {
        (
            "QuorumFresh",
            format!("{fresh} of {observable} observable nodes have fresh reports."),
        )
    };
    condition(REPORTS_STALE, active, generation, reason, message, &now)
}

/// `DeploymentHalted` on an `UpdateGroupSet`: the regression verdict, with its evidence count.
pub fn deployment_halted(
    generation: Option<i64>,
    halted: &[crate::HaltedDeployment],
    now: chrono::DateTime<chrono::Utc>,
) -> ResourceCondition {
    let active = !halted.is_empty();
    let (reason, message) = if active {
        (
            "RegressionEvidence",
            halted
                .iter()
                .map(|halt| {
                    format!(
                        "deployment {} is halted: {} node(s) attempted it and rolled back",
                        halt.deployment, halt.evidence
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    } else {
        (
            "NoRegression",
            "No staged deployment has reached the set's regression threshold.".into(),
        )
    };
    condition(DEPLOYMENT_HALTED, active, generation, reason, message, &now)
}

/// `ReconcileFailing` on an `UpdateGroupSet`: the loop itself erred on consecutive passes. One
/// failed pass is an ordinary transient (the next pass retries within a second); two in a row is a
/// loop that is not converging.
pub fn reconcile_failing(
    generation: Option<i64>,
    consecutive_failures: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> ResourceCondition {
    let active = consecutive_failures >= 2;
    // The active message carries no live count: the streak grows every failed pass, and a message
    // that grows with it forced an apiserver write per set per second for as long as the loop was
    // down — the writer skips identical documents, which only works if the document stabilizes.
    let (reason, message) = if active {
        (
            "ConsecutiveFailures",
            "The reconcile loop has failed consecutive passes (see controller logs).".to_string(),
        )
    } else {
        ("Reconciling", "The reconcile loop is passing.".into())
    };
    condition(RECONCILE_FAILING, active, generation, reason, message, &now)
}

/// Merge a freshly computed condition over the one the resource already carries: standard k8s
/// condition semantics. When the status did not change, the previous `lastTransitionTime` is kept
/// — the timestamp marks transitions, not observations. Returns the condition to publish and
/// whether this IS a transition the webhook should deliver: `False→True`, `True→False`, or a first
/// observation that is already `True` (an alert that exists from its first evaluation must still
/// fire once).
pub fn carry_transition(
    previous: Option<&ResourceCondition>,
    mut next: ResourceCondition,
) -> (ResourceCondition, bool) {
    match previous {
        Some(previous) if previous.status == next.status => {
            next.last_transition_time = previous.last_transition_time.clone();
            (next, false)
        }
        Some(_) => (next, true),
        None => {
            let fires = next.status == "True";
            (next, fires)
        }
    }
}

/// The condition of `condition_type` a resource's status currently carries, if any.
pub fn existing<'a>(
    conditions: &'a [ResourceCondition],
    condition_type: &str,
) -> Option<&'a ResourceCondition> {
    conditions
        .iter()
        .find(|condition| condition.condition_type == condition_type)
}

/// One condition transition, as the webhook delivers it: resource, condition, state, reason,
/// evidence, generation, timestamp. One JSON document per transition, no batching, no templating —
/// fan-out, dedup windows, paging policy and formatting belong to the receiver.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlertEvent {
    /// `Kind/name`, e.g. `UpdateGroup/edge`.
    pub resource: String,
    pub condition: String,
    /// `True` or `False`.
    pub state: String,
    pub reason: String,
    /// The condition's message — the evidence behind the verdict.
    pub evidence: String,
    pub generation: Option<i64>,
    /// RFC 3339 instant of the transition.
    pub timestamp: String,
}

impl AlertEvent {
    pub fn from_condition(kind: &str, name: &str, condition: &ResourceCondition) -> Self {
        Self {
            resource: format!("{kind}/{name}"),
            condition: condition.condition_type.clone(),
            state: condition.status.clone(),
            reason: condition.reason.clone(),
            evidence: condition.message.clone(),
            generation: condition.observed_generation,
            timestamp: condition.last_transition_time.clone(),
        }
    }
}

/// How long one delivery attempt may take — the same network deadline every other external POST in
/// this crate uses (see `subscription::deliver_updates`).
const DELIVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Attempts per event: the first try plus a bounded retry through the shared backoff, then drop.
/// The condition on the resource remains the durable record, so a dropped webhook loses a
/// notification, not a fact.
const DELIVERY_ATTEMPTS: u32 = 3;

/// The one webhook sink (`UPDATED_ALERT_URL`). Delivery is bounded, serialized — one in-flight
/// request — and never blocks the reconcile loop: the loop hands a pass's transitions to
/// [`AlertSink::spawn`] and a single background worker drains them.
///
/// Memory behind a slow receiver is bounded by COALESCING, not by dropping: the pending set keeps
/// one event per `(resource, condition)`, the newest, so it can never exceed the fleet's resource
/// count — and a later transition REPLACES an undelivered earlier one. That is the correct
/// semantics for a level-triggered condition: what the receiver must eventually learn is the
/// current state, and dropping whole batches lost exactly the recovery clears.
pub struct AlertSink {
    url: String,
    /// A mounted secret file holding the bearer token, re-read per delivery so a rotated secret
    /// takes effect without a restart. `None` sends no Authorization header.
    token_file: Option<PathBuf>,
    client: reqwest::Client,
    /// The delivery queue: undelivered transitions (newest per `(resource, condition)`) and
    /// whether a drain worker is running, under ONE lock — every enqueue/dequeue observes both
    /// atomically, so an event enqueued while the worker is shutting down is never stranded and
    /// no lock-ordering argument is needed.
    queue: std::sync::Mutex<AlertQueue>,
}

#[derive(Default)]
struct AlertQueue {
    pending: std::collections::BTreeMap<(String, String), AlertEvent>,
    draining: bool,
}

impl AlertSink {
    pub fn new(url: String, token_file: Option<PathBuf>) -> Result<Self, String> {
        // A URL that cannot be parsed would otherwise fail on every delivery, forever, behind a
        // per-event warning — a muted alert channel on a running controller. Its sibling setting
        // (the metrics address) fails fast at startup; this one does too.
        let parsed =
            reqwest::Url::parse(&url).map_err(|error| format!("parsing {url:?}: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!(
                "the alert URL must be http or https, got {:?}",
                parsed.scheme()
            ));
        }
        // Same egress discipline as the subscription webhook: never follow a redirect off the
        // operator-configured host.
        let client = reqwest::Client::builder()
            .timeout(DELIVERY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("building the alert HTTP client: {error}"))?;
        Ok(Self {
            url,
            token_file,
            client,
            queue: std::sync::Mutex::new(AlertQueue::default()),
        })
    }

    /// Hand a pass's transitions over for background delivery. Returns immediately; each event
    /// replaces any undelivered predecessor for the same `(resource, condition)`, and a drain
    /// worker is started unless one is already running.
    pub fn spawn(self: &std::sync::Arc<Self>, events: Vec<AlertEvent>) {
        if events.is_empty() {
            return;
        }
        let start_worker = {
            let mut queue = self.queue.lock().expect("alert queue");
            for event in events {
                queue
                    .pending
                    .insert((event.resource.clone(), event.condition.clone()), event);
            }
            !std::mem::replace(&mut queue.draining, true)
        };
        if start_worker {
            let sink = self.clone();
            tokio::spawn(async move { sink.drain().await });
        }
    }

    /// Deliver pending transitions one at a time until none remain. The empty check and the
    /// worker-exit flip are one atomic step under the queue lock, so an event enqueued
    /// concurrently either finds the worker still marked running (and is drained by it) or finds
    /// it stopped (and starts a new one) — never neither.
    async fn drain(self: std::sync::Arc<Self>) {
        loop {
            let next = {
                let mut queue = self.queue.lock().expect("alert queue");
                match queue.pending.pop_first() {
                    Some((_, event)) => Some(event),
                    None => {
                        queue.draining = false;
                        None
                    }
                }
            };
            let Some(event) = next else { return };
            self.deliver(&event).await;
        }
    }

    /// Deliver one transition: POST, deadline, bounded retry with the shared backoff, then drop.
    async fn deliver(&self, event: &AlertEvent) {
        let Ok(body) = serde_json::to_vec(event) else {
            return;
        };
        for attempt in 0..DELIVERY_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(foundation::time::exponential_backoff(
                    std::time::Duration::from_millis(500),
                    attempt - 1,
                    4,
                    std::time::Duration::from_secs(5),
                ))
                .await;
            }
            // The credential is read INSIDE the attempt loop, so a transient failure to read it
            // costs one attempt and a backoff like any other failure. Read once outside, a
            // millisecond-wide window — an operator's truncate-then-write rotation — dropped the
            // transition with zero retries, and the webhook is edge-triggered: the next transition
            // for that condition is the CLEAR, which pages nobody, so the whole firing period went
            // unannounced.
            let token = match &self.token_file {
                // FAIL CLOSED on the credential: a configured token must never degrade to an
                // unauthenticated POST. Every attempt is spent on reading it, and the condition on
                // the resource remains the durable record either way.
                Some(path) => match tokio::fs::read_to_string(path).await {
                    // An EMPTY read is a credential failure too, not a token: a Secret key set to
                    // the empty string, a key not yet populated, or a truncate-then-write rotation
                    // caught mid-flight all read `Ok("")`, and `bearer_auth("")` builds the
                    // perfectly legal header `Bearer ` — the unauthenticated POST this arm exists
                    // to prevent.
                    Ok(token) if token.trim().is_empty() => {
                        tracing::warn!(path = %path.display(), "alert bearer-token file is empty; skipping this attempt");
                        continue;
                    }
                    Ok(token) => Some(token.trim().to_string()),
                    Err(error) => {
                        tracing::warn!(%error, path = %path.display(), "alert bearer-token file is unreadable; skipping this attempt");
                        continue;
                    }
                },
                None => None,
            };
            let mut request = self
                .client
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body.clone());
            if let Some(token) = &token {
                request = request.bearer_auth(token);
            }
            match request.send().await {
                Ok(response) if response.status().is_success() => return,
                Ok(response) => tracing::warn!(
                    status = %response.status(),
                    condition = %event.condition,
                    resource = %event.resource,
                    "alert webhook refused the transition"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    condition = %event.condition,
                    resource = %event.resource,
                    "alert webhook delivery failed"
                ),
            }
        }
        tracing::warn!(
            condition = %event.condition,
            resource = %event.resource,
            "dropping alert transition after bounded retries; the condition on the resource \
             remains the durable record"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-08-08T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// RolloutStuck, both directions: it rises only once a STAGING group has sat past the
    /// threshold with no progress, and clears the moment staging ends or progress resumes.
    #[test]
    fn rollout_stuck_rises_past_the_threshold_and_clears_both_ways() {
        let start = now();
        let mut tracker = ProgressTracker::new();
        let target = Some("identity-a".to_string());

        let since = tracker.observe("g", target.clone(), 1, start);
        assert_eq!(since, start);

        // Half an hour of no progress: staging but not stuck.
        let later = start + chrono::Duration::seconds(1800);
        let since = tracker.observe("g", target.clone(), 1, later);
        let stuck = rollout_stuck(Some(1), true, since, DEFAULT_STUCK_AFTER_SECONDS, later);
        assert_eq!(stuck.status, "False");
        assert_eq!(stuck.reason, "Progressing");

        // Past the threshold: stuck.
        let wedged = start + chrono::Duration::seconds(3601);
        let since = tracker.observe("g", target.clone(), 1, wedged);
        let stuck = rollout_stuck(Some(1), true, since, DEFAULT_STUCK_AFTER_SECONDS, wedged);
        assert_eq!(stuck.status, "True");
        assert_eq!(stuck.reason, "NoNewSettledNode");

        // A node newly settled resets the clock and the condition clears.
        let progressed = wedged + chrono::Duration::seconds(1);
        let since = tracker.observe("g", target.clone(), 2, progressed);
        assert_eq!(since, progressed);
        let stuck = rollout_stuck(
            Some(1),
            true,
            since,
            DEFAULT_STUCK_AFTER_SECONDS,
            progressed,
        );
        assert_eq!(stuck.status, "False");

        // Not staging at all: never stuck, however old the mark.
        let idle = progressed + chrono::Duration::seconds(999_999);
        let since = tracker.observe("g", target, 2, idle);
        let stuck = rollout_stuck(Some(1), false, since, DEFAULT_STUCK_AFTER_SECONDS, idle);
        assert_eq!(stuck.status, "False");
        assert_eq!(stuck.reason, "NotStaging");
    }

    /// A retarget mid-wedge is new work, not an hour-old stall: the changed target identity resets
    /// the stuck clock.
    #[test]
    fn a_retarget_resets_the_stuck_clock() {
        let start = now();
        let mut tracker = ProgressTracker::new();
        tracker.observe("g", Some("a".into()), 1, start);
        let wedged = start + chrono::Duration::seconds(7200);
        let since = tracker.observe("g", Some("b".into()), 1, wedged);
        assert_eq!(since, wedged, "the new admission starts a fresh clock");
    }

    /// ReportsStale, both directions: staleness within `maxUnavailable` is the ordinary shape of
    /// a staged rollout (the moving node reports nothing while it reboots into its update), so
    /// only staleness EXCEEDING what admission tolerates raises the condition.
    #[test]
    fn reports_stale_tracks_the_admission_quorum() {
        assert_eq!(reports_stale(Some(1), 3, 3, 1, now()).status, "False");
        // One stale node inside a budget of one is a rollout in progress, not an alert.
        assert_eq!(reports_stale(Some(1), 2, 3, 1, now()).status, "False");
        assert_eq!(reports_stale(Some(1), 1, 3, 1, now()).status, "True");
        // A budget of two tolerates two stale nodes.
        assert_eq!(reports_stale(Some(1), 1, 3, 2, now()).status, "False");
        assert_eq!(reports_stale(Some(1), 0, 3, 2, now()).status, "True");
        // A single-node group can never exceed its own budget; its wedges raise RolloutStuck.
        assert_eq!(reports_stale(Some(1), 0, 1, 1, now()).status, "False");
        // Nothing observable: nothing to say.
        assert_eq!(reports_stale(Some(1), 0, 0, 1, now()).status, "False");
    }

    #[test]
    fn deployment_halted_projects_the_regression_verdict_with_its_evidence() {
        let halted = deployment_halted(
            Some(2),
            &[crate::HaltedDeployment {
                deployment: "app-v2".into(),
                evidence: 3,
            }],
            now(),
        );
        assert_eq!(halted.status, "True");
        assert!(halted.message.contains("app-v2"));
        assert!(halted.message.contains('3'));
        assert_eq!(deployment_halted(Some(2), &[], now()).status, "False");
    }

    #[test]
    fn reconcile_failing_needs_consecutive_failures() {
        assert_eq!(reconcile_failing(Some(1), 0, now()).status, "False");
        assert_eq!(reconcile_failing(Some(1), 1, now()).status, "False");
        assert_eq!(reconcile_failing(Some(1), 2, now()).status, "True");
    }

    /// Transitions only: an unchanged status keeps its original `lastTransitionTime` and fires no
    /// webhook; a flip in either direction fires; a first observation fires only when it is
    /// already `True`.
    #[test]
    fn carry_transition_fires_on_transitions_only() {
        let active = rollout_stuck(
            Some(1),
            true,
            now() - chrono::Duration::seconds(9999),
            3600,
            now(),
        );
        let (first, fires) = carry_transition(None, active.clone());
        assert!(fires, "a condition born True must fire once");

        let (repeat, fires) = carry_transition(Some(&first), active.clone());
        assert!(!fires, "no repeats while the state holds");
        assert_eq!(
            repeat.last_transition_time, first.last_transition_time,
            "the transition time marks the transition, not the observation"
        );

        let cleared = rollout_stuck(Some(1), false, now(), 3600, now());
        let (_, fires) = carry_transition(Some(&first), cleared.clone());
        assert!(fires, "True→False is a transition and is delivered");

        let (_, fires) = carry_transition(None, cleared);
        assert!(
            !fires,
            "a condition born False is the steady state, not news"
        );
    }

    /// The webhook client against a local listener: transitions are POSTed as one JSON document
    /// with the bearer token, a refused delivery is retried the bounded number of times and then
    /// dropped, and the deadline bounds a hung receiver.
    #[tokio::test]
    async fn the_webhook_delivers_transitions_and_drops_after_bounded_retries() {
        use axum::routing::post;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let hits = Arc::new(AtomicU32::new(0));
        let seen = Arc::new(tokio::sync::Mutex::new(
            Vec::<(Option<String>, AlertEvent)>::new(),
        ));
        let refuse = Arc::new(AtomicU32::new(0));
        let app = axum::Router::new().route(
            "/alerts",
            post({
                let hits = hits.clone();
                let seen = seen.clone();
                let refuse = refuse.clone();
                move |headers: axum::http::HeaderMap, body: axum::Json<AlertEvent>| {
                    let hits = hits.clone();
                    let seen = seen.clone();
                    let refuse = refuse.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let token = headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        seen.lock().await.push((token, body.0));
                        if refuse.load(Ordering::SeqCst) > 0 {
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            axum::http::StatusCode::NO_CONTENT
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let token_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(token_file.path(), "s3cret\n").unwrap();
        let sink = AlertSink::new(
            format!("http://{addr}/alerts"),
            Some(token_file.path().to_path_buf()),
        )
        .unwrap();

        let event = AlertEvent {
            resource: "UpdateGroup/edge".into(),
            condition: ROLLOUT_STUCK.into(),
            state: "True".into(),
            reason: "NoNewSettledNode".into(),
            evidence: "stuck".into(),
            generation: Some(4),
            timestamp: "2026-08-08T12:00:00Z".into(),
        };
        sink.deliver(&event).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a delivered event is not retried"
        );
        {
            let seen = seen.lock().await;
            let (token, received) = &seen[0];
            assert_eq!(token.as_deref(), Some("Bearer s3cret"));
            assert_eq!(received, &event);
        }

        // A refusing receiver gets the bounded retries and the event is then dropped — deliver()
        // returns rather than blocking forever.
        refuse.store(1, Ordering::SeqCst);
        sink.deliver(&event).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1 + DELIVERY_ATTEMPTS,
            "bounded retries, then drop"
        );

        // FAIL CLOSED on an EMPTY token, not only on an unreadable one: a Secret key set to the
        // empty string, a key not yet populated, or a truncate-then-write rotation caught
        // mid-flight all read `Ok("")`, and `bearer_auth("")` builds the perfectly legal header
        // `Bearer ` — an unauthenticated POST carrying the controller's rollout metadata.
        refuse.store(0, Ordering::SeqCst);
        let before = hits.load(Ordering::SeqCst);
        std::fs::write(token_file.path(), "  \n").unwrap();
        sink.deliver(&event).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before,
            "a configured token that reads back empty skips the delivery, exactly as an \
             unreadable one does"
        );

        // …but it spends an ATTEMPT, not the transition. A credential read is as transient as the
        // POST beside it (an operator's truncate-then-write rotation is milliseconds wide), and the
        // webhook is edge-triggered: a fire dropped at the first read is never re-sent while the
        // condition stays True, because the next transition for it is the CLEAR, which pages
        // nobody. Here the rotation is repaired while the first backoff is still running.
        let before = hits.load(Ordering::SeqCst);
        std::fs::write(token_file.path(), "").unwrap();
        let path = token_file.path().to_path_buf();
        let repair = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            std::fs::write(&path, "rotated\n").unwrap();
        });
        sink.deliver(&event).await;
        repair.await.unwrap();
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before + 1,
            "a credential unreadable on the first attempt is retried, not dropped"
        );
        {
            let seen = seen.lock().await;
            let (token, _) = seen.last().unwrap();
            assert_eq!(
                token.as_deref(),
                Some("Bearer rotated"),
                "…and the retry carries the token the operator has meanwhile fixed"
            );
        }
    }

    /// The pending set coalesces to the NEWEST transition per (resource, condition): while the
    /// receiver is slow, a later clear replaces an undelivered earlier fire instead of queueing
    /// behind it or being dropped — the receiver ends on the current state, which is the whole
    /// contract of a level-triggered condition.
    #[tokio::test]
    async fn spawned_transitions_coalesce_to_the_newest_per_condition() {
        use axum::routing::post;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let seen = Arc::new(tokio::sync::Mutex::new(Vec::<AlertEvent>::new()));
        let hits = Arc::new(AtomicU32::new(0));
        let app = axum::Router::new().route(
            "/alerts",
            post({
                let seen = seen.clone();
                let hits = hits.clone();
                move |body: axum::Json<AlertEvent>| {
                    let seen = seen.clone();
                    let hits = hits.clone();
                    async move {
                        // The FIRST delivery is slow, so everything spawned meanwhile must
                        // coalesce in the pending set.
                        if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        }
                        seen.lock().await.push(body.0);
                        axum::http::StatusCode::NO_CONTENT
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let event = |state: &str, reason: &str| AlertEvent {
            resource: "UpdateGroup/edge".into(),
            condition: ROLLOUT_STUCK.into(),
            state: state.into(),
            reason: reason.into(),
            evidence: String::new(),
            generation: Some(1),
            timestamp: "2026-08-08T12:00:00Z".into(),
        };
        let sink =
            std::sync::Arc::new(AlertSink::new(format!("http://{addr}/alerts"), None).unwrap());
        sink.spawn(vec![event("True", "NoNewSettledNode")]);
        // Let the worker take the first event in flight, then pile up two more transitions for
        // the same condition while the receiver is stalled.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        sink.spawn(vec![event("False", "Progressing")]);
        sink.spawn(vec![event("False", "NotStaging")]);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if seen.lock().await.len() >= 2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "deliveries never finished"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Settle briefly: no third delivery may arrive — the middle transition was replaced.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let seen = seen.lock().await;
        assert_eq!(
            seen.len(),
            2,
            "the superseded middle transition is never sent"
        );
        assert_eq!(seen[0].state, "True");
        assert_eq!(
            seen[1].reason, "NotStaging",
            "the receiver ends on the NEWEST state for the condition"
        );
    }
}
