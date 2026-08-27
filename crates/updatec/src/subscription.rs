//! Delivery for [`UpdateSubscription`](crate::UpdateSubscription): a generic webhook push announcing
//! that a repository published a new generation. This is the "notify me on updates" path — no S3
//! event notifications, no polling by the subscriber. The publisher pushes.
//!
//! Delivery rides the controller's single-writer reconcile, so it is at-least-once without a queue.
//! Each subscription keeps a per-repository high-water mark in its status; every reconcile we deliver
//! one event per generation from that mark up to the currently published version, advancing the mark
//! only on a successful `POST`. A subscriber that was down is caught up on the next tick; nothing is
//! skipped, and nothing is re-delivered once acknowledged. A webhook that stays down never blocks
//! publishing — its failure is recorded in the subscription's status and retried, never propagated.
//!
//! "Nothing is skipped" holds across subscribers as well as generations, and that is what the
//! per-subscription `lastAttemptTime` cursor is for: each pass serves the least recently attempted
//! subscriptions first, so the aggregate delivery budget rotates instead of being spent on the same
//! head of the list every second. Whatever the budget does not reach says so on its own CR — unless
//! that CR already reports a real delivery failure, which is the more useful thing for it to say.

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::ResourceExt;
use serde::Serialize;

use crate::webhook::{hmac_key, signature, SIGNATURE_HEADER};
use crate::{ResourceCondition, UpdateSubscription};

/// One update event delivered to a subscriber. The immutable, content-addressed history lives in S3;
/// this only announces "repository `repository` advanced to generation `version`". The subscriber
/// fetches `<public_url>/<prefix>/metadata/<version>.snapshot.json` — signed and immutable — to learn
/// exactly what changed at that generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEvent {
    pub repository: String,
    pub namespace: String,
    pub prefix: String,
    pub public_url: String,
    pub version: u64,
    pub delivered_at: String,
}

/// How many missed generations one subscription may be caught up on in a single reconcile. Delivery
/// is synchronous and inline in the reconcile loop, and the catch-up length is unbounded (a new
/// subscription starts at mark 0 against a repository that may have published tens of thousands of
/// generations). The mark is persisted from whatever was actually acknowledged, so a longer backlog
/// simply resumes next pass instead of holding rollout, telemetry, and publication hostage.
const MAX_EVENTS_PER_PASS: usize = 64;

/// Total time all subscription delivery may consume in one reconcile. Bounds the *aggregate*: many
/// slow-but-succeeding subscribers must not add up to a stalled control plane the way one long
/// catch-up must not.
const DELIVERY_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The one immutable publication identity every delivery in a pass announces.
///
/// Keeping these fields together prevents the list, event encoder, and status writer from being
/// handed subtly different spellings of a repository generation. The delivery machinery may vary
/// the subscriber and high-water mark; this value is the authority for everything else.
#[derive(Clone, Copy)]
pub struct DeliveryContext<'a> {
    pub repository: &'a str,
    pub namespace: &'a str,
    pub prefix: &'a str,
    pub public_url: &'a str,
    pub version: u64,
    pub now: &'a str,
}

/// The one delivery client for the process. A `reqwest::Client` IS its connection pool, so building
/// one per call — this runs on every reconcile pass, once a second per repository — rebuilt the TLS
/// config and resolver each time and threw away keep-alive, making every webhook `POST` pay a fresh
/// TCP+TLS handshake. Held the way [`crate::alerts::AlertSink`] holds its client, and built lazily
/// so a namespace with no subscriptions never builds one at all.
///
/// Webhook URLs are operator-supplied (inside the CRD trust boundary), but redirects are refused so
/// a webhook cannot bounce the signed event body to an internal-only endpoint (cloud metadata,
/// in-cluster services) that the configured host would not otherwise reach.
static DELIVERY_CLIENT: std::sync::LazyLock<std::io::Result<reqwest::Client>> =
    std::sync::LazyLock::new(|| {
        updated::http::outbound_client(updated::http::OutboundDeadline::Total(
            std::time::Duration::from_secs(10),
        ))
    });

/// Whether a subscription with the given optional `repositoryRef` covers `repository`. `None` means
/// every repository in the namespace; `Some(name)` means only that one.
fn covers(repository_ref: Option<&str>, repository: &str) -> bool {
    repository_ref.is_none_or(|name| name == repository)
}

/// The generations still owed to a subscriber at high-water mark `mark`, given the current published
/// `version`: `mark + 1 ..= version`, one event each. Empty when the subscriber is already current
/// (or somehow ahead, which is treated as current — the mark never moves backward).
fn pending(mark: u64, version: u64) -> impl Iterator<Item = u64> {
    // The `mark < version` guard is what makes `mark + 1` unreachable at `u64::MAX`: `mark` is read
    // back from the subscription's `.status`, which anyone with patch-status on the CR can set, and
    // release builds keep `overflow-checks`, so an unguarded increment would panic the reconcile
    // loop on a hostile mark. A mark at or ahead of `version` is owed nothing either way.
    (mark < version)
        .then(|| (mark + 1)..=version)
        .into_iter()
        .flatten()
}

/// Deliver pending update events to every subscription that covers `repository`, advancing each
/// subscription's per-repository high-water mark to `version` on success. Only apiserver failures
/// (listing subscriptions) are returned; a failed webhook `POST` is recorded in that subscription's
/// status and left for the next reconcile, so one broken subscriber never blocks the others or the
/// publish.
pub async fn deliver_updates(
    subscriptions: &Api<UpdateSubscription>,
    secrets: &Api<Secret>,
    context: DeliveryContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let http = match &*DELIVERY_CLIENT {
        Ok(http) => http,
        Err(error) => {
            return Err(format!("building the subscription delivery client: {error}").into())
        }
    };
    deliver_pass(
        subscriptions,
        secrets,
        http,
        context,
        std::time::Instant::now() + DELIVERY_BUDGET,
    )
    .await
}

/// One delivery pass, against an explicit `deadline` so the budget rule is testable: every
/// subscription owed an event either gets a delivery attempt or gets told it was deferred, and
/// nothing falls between the two.
async fn deliver_pass(
    subscriptions: &Api<UpdateSubscription>,
    secrets: &Api<Secret>,
    http: &reqwest::Client,
    context: DeliveryContext<'_>,
    deadline: std::time::Instant,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut owed: Vec<(UpdateSubscription, u64)> = subscriptions
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|sub| {
            covers(
                sub.spec.repository_ref.as_ref().map(|r| r.name.as_str()),
                context.repository,
            )
        })
        .map(|sub| {
            let mark = delivered_mark(&sub, context.repository);
            (sub, mark)
        })
        .filter(|(_, mark)| pending(*mark, context.version).next().is_some())
        .collect();
    owed.sort_by(|(left, _), (right, _)| delivery_order(left).cmp(&delivery_order(right)));

    // Indexed rather than iterated: the budget is checked BEFORE the subscription is taken, so the
    // one the pass stops at is still in the deferral half below. Breaking out of a `for` loop over
    // the iterator consumed that subscription first, and a subscription in neither half gets no
    // delivery AND no condition — the invisible starvation this whole cursor exists to end.
    let mut reached = 0;
    while reached < owed.len() && std::time::Instant::now() < deadline {
        let (sub, mark) = &owed[reached];
        reached += 1;
        deliver_one(subscriptions, secrets, http, sub, *mark, context, deadline).await;
    }
    // Whatever the budget did not reach is DEFERRED, not skipped: it keeps its (older) attempt
    // stamp, so the next pass serves it first, and it says so on its own CR.
    for (sub, mark) in &owed[reached..] {
        defer(subscriptions, sub, context.repository, *mark, context.now).await;
    }
    Ok(())
}

/// Tell one subscription the budget never got to it — the whole rule, in one place, for both the
/// subscriptions [`deliver_pass`] never reached and the one it entered but could not attempt.
///
/// The log line and the status write are on the TRANSITION only: this pass runs once a second, so a
/// subscriber that stays behind for an hour would otherwise be an hour of status writes and 3600
/// identical warnings. And a deferral never overwrites a real delivery failure, whose detail (the
/// HTTP status, the connection error) an operator needs more than "the budget ran out" — see
/// [`deferral_says_nothing_new`].
async fn defer(
    subscriptions: &Api<UpdateSubscription>,
    sub: &UpdateSubscription,
    repository: &str,
    mark: u64,
    now: &str,
) {
    if deferral_says_nothing_new(sub) {
        return;
    }
    let name = sub.name_any();
    tracing::warn!(
        repository,
        subscription = %name,
        "subscription delivery budget spent before this subscriber was attempted; it is first in \
         line next reconcile"
    );
    record(subscriptions, sub, repository, mark, now, Outcome::Deferred).await;
}

/// This subscription's high-water mark for `repository` — the last generation it acknowledged.
fn delivered_mark(sub: &UpdateSubscription, repository: &str) -> u64 {
    sub.status
        .as_ref()
        .and_then(|status| status.delivered_versions.get(repository))
        .copied()
        .unwrap_or(0)
}

/// The delivery cursor: least-recently-ATTEMPTED first, name as the tiebreak so the order is
/// total and deterministic. A never-attempted subscription sorts ahead of every attempted one.
///
/// Iterating in apiserver (name) order and restarting at the first name every pass meant a
/// subscriber behind a consistently slow one was never reached at all — no delivery, and no
/// `record`, so its CR froze at whatever it last said and the starvation was invisible. The stamp
/// advances only on a real attempt, so a deferred subscription stays at the head of the line.
fn delivery_order(sub: &UpdateSubscription) -> (&str, String) {
    (
        sub.status
            .as_ref()
            .and_then(|status| status.last_attempt_time.as_deref())
            .unwrap_or_default(),
        sub.name_any(),
    )
}

/// Whether recording a deferral would tell an operator nothing the subscription's `Ready` condition
/// does not already say — or, worse, less.
///
/// Two cases, both "leave the condition alone". It already carries the deferral, so re-recording it
/// writes the same status again. Or it carries a real delivery FAILURE: "the budget never reached
/// you" is the weaker claim of the two, and overwriting the failure erased the detail (the HTTP
/// status, the connection error) an operator needs, once a second, for as long as the backlog and
/// the broken webhook coexisted. A genuine failure stands until a genuine attempt replaces it.
fn deferral_says_nothing_new(sub: &UpdateSubscription) -> bool {
    sub.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|condition| {
            condition.condition_type == crate::status_contract::READY_CONDITION
                && (condition.reason == DEFERRED_REASON || condition.reason == FAILED_REASON)
        })
    })
}

/// Deliver pending generations to a single subscription, in order, stopping at the first failure —
/// and at [`MAX_EVENTS_PER_PASS`] or `deadline`, whichever comes first. The high-water mark and
/// status condition are written from whatever was actually acknowledged, so a bounded pass is
/// simply progress: the remainder resumes next reconcile.
async fn deliver_one(
    subscriptions: &Api<UpdateSubscription>,
    secrets: &Api<Secret>,
    http: &reqwest::Client,
    sub: &UpdateSubscription,
    mark: u64,
    context: DeliveryContext<'_>,
    deadline: std::time::Instant,
) {
    let webhook_url = match updated::http::network_endpoint(
        &sub.spec.webhook.url,
        updated::http::EndpointTransport::HttpOrHttps,
        "subscription webhook URL",
    ) {
        Ok(url) => url,
        Err(error) => {
            record(
                subscriptions,
                sub,
                context.repository,
                mark,
                context.now,
                Outcome::Failed(&error.to_string()),
            )
            .await;
            return;
        }
    };

    // Resolve the signing key once (if any) for the whole catch-up run.
    let key = match &sub.spec.webhook.secret_ref {
        Some(reference) => match hmac_key(secrets, &reference.name).await {
            Ok(key) => Some(key),
            Err(error) => {
                record(
                    subscriptions,
                    sub,
                    context.repository,
                    mark,
                    context.now,
                    Outcome::Failed(&format!("resolving webhook secret: {error}")),
                )
                .await;
                return;
            }
        },
        None => None,
    };

    let mut delivered = mark;
    // Whether this subscription got an ATTEMPT at all. The budget can expire between
    // `deliver_pass`'s check and here — resolving the webhook Secret is a full apiserver GET — and
    // recording that as a delivery reported `Ready=True` over an untouched backlog AND stamped
    // `lastAttemptTime`, sending a subscriber that was never contacted to the back of the fairness
    // queue. That is the starvation the cursor exists to end, so zero attempts is recorded as the
    // deferral it is.
    let mut attempted = false;
    for target in pending(mark, context.version).take(MAX_EVENTS_PER_PASS) {
        if std::time::Instant::now() >= deadline {
            break;
        }
        attempted = true;
        let event = UpdateEvent {
            repository: context.repository.to_string(),
            namespace: context.namespace.to_string(),
            prefix: context.prefix.to_string(),
            public_url: context.public_url.to_string(),
            version: target,
            delivered_at: context.now.to_string(),
        };
        let body = match serde_json::to_vec(&event) {
            Ok(body) => body,
            Err(error) => {
                record(
                    subscriptions,
                    sub,
                    context.repository,
                    delivered,
                    context.now,
                    Outcome::Failed(&format!("encoding event: {error}")),
                )
                .await;
                return;
            }
        };
        let mut request = http
            .post(webhook_url.clone())
            .header("content-type", "application/json");
        if let Some(key) = &key {
            request = request.header(SIGNATURE_HEADER, signature(key, &body));
        }
        match request.body(body).send().await {
            Ok(response) if response.status().is_success() => {
                delivered = target;
            }
            Ok(response) => {
                record(
                    subscriptions,
                    sub,
                    context.repository,
                    delivered,
                    context.now,
                    Outcome::Failed(&format!("webhook returned HTTP {}", response.status())),
                )
                .await;
                return;
            }
            Err(error) => {
                let error = updated::http::redacted_reqwest_error(
                    "posting to subscription webhook",
                    &error,
                );
                record(
                    subscriptions,
                    sub,
                    context.repository,
                    delivered,
                    context.now,
                    Outcome::Failed(&error.to_string()),
                )
                .await;
                return;
            }
        }
    }
    if !attempted {
        // The same deferral the subscriptions `deliver_pass` never reached get, through the same
        // writer: this one was entered but never contacted, which is the same claim.
        defer(subscriptions, sub, context.repository, mark, context.now).await;
        return;
    }
    record(
        subscriptions,
        sub,
        context.repository,
        delivered,
        context.now,
        Outcome::Delivered,
    )
    .await;
}

/// Why a subscription's status is being written this pass. The three cases differ in exactly two
/// ways — whether the `Ready` condition holds, and whether the delivery cursor advances — so they
/// are one enum read by one writer rather than three status paths that could drift.
enum Outcome<'a> {
    /// Everything owed at the start of the pass was delivered and acknowledged.
    Delivered,
    /// A delivery attempt failed; `detail` says how.
    Failed(&'a str),
    /// The pass spent its budget on earlier subscribers and never reached this one.
    Deferred,
}

/// The `reason` a deferred subscription carries, and the marker that keeps the deferral from being
/// re-written every second for as long as the backlog lasts.
const DEFERRED_REASON: &str = "DeliveryDeferred";

/// The `reason` a subscription whose delivery actually failed carries. Read back as well as
/// written: a deferral must not overwrite it (see [`deferral_says_nothing_new`]).
const FAILED_REASON: &str = "DeliveryFailed";

/// Persist a subscription's delivery progress: advance the per-repository mark to `delivered`,
/// merge the `Ready` condition for `outcome` through the shared condition invariant, and stamp the
/// times. Best-effort — a failed status patch is logged, never propagated, since delivery must not
/// block the publish.
///
/// `lastAttemptTime` is stamped for an attempt and NOT for a deferral: it is the cursor the next
/// pass orders by, so stamping it here would send the subscription this pass could not reach to the
/// back of the queue again — which is the starvation it exists to end.
async fn record(
    subscriptions: &Api<UpdateSubscription>,
    subscription: &UpdateSubscription,
    repository: &str,
    delivered: u64,
    now: &str,
    outcome: Outcome<'_>,
) {
    let observed = subscription
        .status
        .as_ref()
        .map_or(&[][..], |status| status.conditions.as_slice());
    let status = status_document(observed, repository, delivered, now, outcome);
    let name = subscription.name_any();
    if let Err(error) = subscriptions
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await
    {
        tracing::warn!(subscription = name, error = %error, "recording subscription delivery status");
    }
}

/// The status patch [`record`] writes, built without touching the apiserver so the cursor rule is
/// directly testable.
fn status_document(
    observed: &[ResourceCondition],
    repository: &str,
    delivered: u64,
    now: &str,
    outcome: Outcome<'_>,
) -> serde_json::Value {
    let (ready, reason, message) = match outcome {
        Outcome::Delivered => (
            true,
            "Delivered",
            format!("delivered through generation {delivered}"),
        ),
        Outcome::Failed(detail) => (
            false,
            FAILED_REASON,
            format!("stalled at generation {delivered}: {detail}"),
        ),
        Outcome::Deferred => (
            false,
            DEFERRED_REASON,
            format!(
                "waiting at generation {delivered}: the {}s delivery budget was spent on earlier \
                 subscribers before this one was reached; it is served first next reconcile",
                DELIVERY_BUDGET.as_secs()
            ),
        ),
    };
    let condition = crate::status_contract::condition(
        crate::status_contract::READY_CONDITION,
        ready,
        None,
        reason,
        message,
        // Always stamped, including on the failure paths. An empty transition time is not a
        // "never" a reader can interpret — `kubectl` renders it as an epoch and any consumer
        // sorting conditions by age puts a fresh failure at the bottom.
        now,
    );
    let conditions = crate::alerts::merge_conditions(observed, vec![condition]);
    let mut status = serde_json::json!({
        "deliveredVersions": { repository: delivered },
        "conditions": conditions,
    });
    if matches!(outcome, Outcome::Delivered) {
        status["lastDeliveryTime"] = serde_json::Value::String(now.to_string());
    }
    if !matches!(outcome, Outcome::Deferred) {
        status["lastAttemptTime"] = serde_json::Value::String(now.to_string());
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_scopes_to_a_repository_or_all() {
        assert!(covers(None, "fleet"), "no ref covers every repository");
        assert!(covers(Some("fleet"), "fleet"), "matching ref covers it");
        assert!(!covers(Some("other"), "fleet"), "a different ref does not");
    }

    #[test]
    fn pending_is_one_event_per_missed_generation() {
        assert_eq!(
            pending(0, 3).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "genesis catch-up"
        );
        assert_eq!(
            pending(2, 5).collect::<Vec<_>>(),
            vec![3, 4, 5],
            "partial catch-up"
        );
        assert_eq!(pending(5, 5).count(), 0, "already current owes nothing");
        assert_eq!(
            pending(7, 5).count(),
            0,
            "a mark ahead of current never rewinds"
        );
        assert_eq!(
            pending(u64::MAX, 5).count(),
            0,
            "a saturated mark owes nothing instead of overflowing the reconcile loop"
        );
    }

    /// A subscription carrying only what the delivery cursor reads: when it was last attempted and
    /// what its `Ready` condition says.
    fn subscription(name: &str, last_attempt: Option<&str>, reason: &str) -> UpdateSubscription {
        let mut sub = UpdateSubscription::new(
            name,
            crate::UpdateSubscriptionSpec {
                webhook: crate::WebhookSpec {
                    url: "https://subscriber/hook".into(),
                    secret_ref: None,
                },
                repository_ref: None,
            },
        );
        sub.status = Some(crate::UpdateSubscriptionStatus {
            last_attempt_time: last_attempt.map(str::to_owned),
            conditions: if reason.is_empty() {
                Vec::new()
            } else {
                vec![ResourceCondition {
                    condition_type: "Ready".into(),
                    status: "False".into(),
                    reason: reason.into(),
                    message: String::new(),
                    observed_generation: None,
                    last_transition_time: "2026-08-03T00:00:00Z".into(),
                }]
            },
            ..Default::default()
        });
        sub
    }

    #[test]
    fn the_least_recently_attempted_subscriber_is_served_first() {
        // Name order is the apiserver's, not a fairness rule: "a-slow" first every pass meant
        // "z-starved" behind it was never reached at all once the budget ran out there.
        let mut subscriptions = [
            subscription("a-slow", Some("2026-08-03T12:00:00Z"), "Delivered"),
            subscription("z-starved", Some("2026-08-03T09:00:00Z"), DEFERRED_REASON),
            subscription("m-fresh", Some("2026-08-03T13:00:00Z"), "Delivered"),
        ];
        subscriptions.sort_by(|left, right| delivery_order(left).cmp(&delivery_order(right)));
        assert_eq!(
            subscriptions
                .iter()
                .map(ResourceExt::name_any)
                .collect::<Vec<_>>(),
            vec!["z-starved", "a-slow", "m-fresh"],
        );

        // A subscription nobody has attempted yet outranks every attempted one, whatever its name.
        let mut with_new = [
            subscription("a-slow", Some("2026-08-03T12:00:00Z"), "Delivered"),
            subscription("z-new", None, ""),
        ];
        with_new.sort_by(|left, right| delivery_order(left).cmp(&delivery_order(right)));
        assert_eq!(with_new[0].name_any(), "z-new");
    }

    #[test]
    fn a_deferral_is_visible_on_the_cr_and_does_not_advance_the_cursor() {
        let deferred = status_document(&[], "fleet", 7, "2026-08-03T14:00:00Z", Outcome::Deferred);
        assert_eq!(deferred["deliveredVersions"]["fleet"], 7);
        assert_eq!(deferred["conditions"][0]["reason"], DEFERRED_REASON);
        assert_eq!(deferred["conditions"][0]["status"], "False");
        assert!(
            deferred.get("lastAttemptTime").is_none(),
            "a deferral must not send the subscriber this pass could not reach to the back of the \
             queue"
        );
        // ... while a real attempt does advance it, in both directions.
        for outcome in [Outcome::Delivered, Outcome::Failed("connection refused")] {
            let attempted = status_document(&[], "fleet", 7, "2026-08-03T14:00:00Z", outcome);
            assert_eq!(attempted["lastAttemptTime"], "2026-08-03T14:00:00Z");
        }
        assert_eq!(
            status_document(&[], "fleet", 7, "2026-08-03T14:00:00Z", Outcome::Delivered,)
                ["lastDeliveryTime"],
            "2026-08-03T14:00:00Z"
        );

        // The deferral is recorded once, not once per reconcile for as long as the backlog lasts.
        assert!(deferral_says_nothing_new(&subscription(
            "s",
            Some("2026-08-03T09:00:00Z"),
            DEFERRED_REASON
        )));
        // And never over a real failure: a broken webhook otherwise alternated between the two
        // conditions every pass, periodically erasing the only detail saying WHY it is broken.
        assert!(deferral_says_nothing_new(&subscription(
            "s",
            Some("2026-08-03T09:00:00Z"),
            FAILED_REASON
        )));
        assert!(!deferral_says_nothing_new(&subscription("s", None, "")));
        assert!(!deferral_says_nothing_new(&subscription(
            "s",
            Some("2026-08-03T09:00:00Z"),
            "Delivered"
        )));
    }

    #[test]
    fn subscription_status_uses_the_shared_condition_merge_invariant() {
        let observed = vec![
            ResourceCondition {
                condition_type: "Ready".into(),
                status: "False".into(),
                reason: "EarlierFailure".into(),
                message: "earlier detail".into(),
                observed_generation: None,
                last_transition_time: "2026-08-03T10:00:00Z".into(),
            },
            ResourceCondition {
                condition_type: "Foreign".into(),
                status: "True".into(),
                reason: "OwnedElsewhere".into(),
                message: "must survive a Ready write".into(),
                observed_generation: None,
                last_transition_time: "2026-08-03T09:00:00Z".into(),
            },
        ];

        let failure = status_document(
            &observed,
            "fleet",
            7,
            "2026-08-03T14:00:00Z",
            Outcome::Failed("new detail"),
        );
        assert_eq!(
            failure["conditions"][0]["lastTransitionTime"], "2026-08-03T10:00:00Z",
            "a changed observation in the same state is not a transition"
        );
        assert_eq!(failure["conditions"][1]["type"], "Foreign");
        assert_eq!(
            failure["conditions"][1]["lastTransitionTime"],
            "2026-08-03T09:00:00Z"
        );

        let recovery = status_document(
            &observed,
            "fleet",
            7,
            "2026-08-03T14:00:00Z",
            Outcome::Delivered,
        );
        assert_eq!(
            recovery["conditions"][0]["lastTransitionTime"], "2026-08-03T14:00:00Z",
            "a False-to-True state change is a transition"
        );
    }

    #[tokio::test]
    async fn an_over_budget_pass_leaves_no_owed_subscriber_without_a_status() {
        use axum::http::{Method, StatusCode};
        let recorded: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> = Default::default();
        let client = crate::tests::apiserver({
            let recorded = recorded.clone();
            move |method: &Method, path: &str, body: Vec<u8>| {
                if method == Method::GET {
                    let items = ["a-sub", "b-sub", "c-sub"]
                        .map(|name| serde_json::to_value(subscription(name, None, "")).unwrap());
                    return (
                        StatusCode::OK,
                        serde_json::json!({ "metadata": {}, "items": items }),
                    );
                }
                let name = path
                    .trim_end_matches("/status")
                    .rsplit('/')
                    .next()
                    .expect("a named resource")
                    .to_string();
                let patch: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let reason = patch["status"]["conditions"][0]["reason"]
                    .as_str()
                    .expect("a Ready condition")
                    .to_string();
                recorded.lock().unwrap().push((name.clone(), reason));
                (
                    StatusCode::OK,
                    serde_json::to_value(subscription(&name, None, "")).unwrap(),
                )
            }
        });

        // A budget that is already spent, so the pass reaches nobody. Every subscriber owed an
        // event must still learn that from its own CR — INCLUDING the one the loop stopped at,
        // which an iterator had already consumed by the time it broke out: that subscriber got no
        // delivery and no condition, and its starvation was invisible on the only object an
        // operator looks at.
        deliver_pass(
            &Api::namespaced(client.clone(), "prod"),
            &Api::namespaced(client, "prod"),
            &reqwest::Client::new(),
            DeliveryContext {
                repository: "fleet",
                namespace: "prod",
                prefix: "tenant/routing",
                public_url: "https://cdn.example/",
                version: 5,
                now: "2026-08-03T14:00:00Z",
            },
            std::time::Instant::now(),
        )
        .await
        .unwrap();

        let mut recorded = recorded.lock().unwrap().clone();
        recorded.sort();
        assert_eq!(
            recorded,
            ["a-sub", "b-sub", "c-sub"]
                .map(|name| (name.to_string(), DEFERRED_REASON.to_string()))
                .to_vec(),
            "every owed subscription is either delivered to or told it was deferred"
        );
    }

    /// The budget can run out INSIDE `deliver_one` — resolving the webhook Secret is a full
    /// apiserver GET — leaving the subscription with the whole backlog undelivered and not one
    /// attempt made. Recording that as a delivery reported `Ready=True` over an untouched backlog
    /// and stamped `lastAttemptTime`, sending a subscriber nobody contacted to the back of the
    /// fairness queue: the starvation the cursor exists to end, dressed as success.
    #[tokio::test]
    async fn a_subscriber_the_budget_never_attempted_is_deferred_not_reported_delivered() {
        use axum::http::{Method, StatusCode};
        let recorded: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let client = crate::tests::apiserver({
            let recorded = recorded.clone();
            move |_: &Method, _: &str, body: Vec<u8>| {
                let patch: serde_json::Value = serde_json::from_slice(&body).unwrap();
                recorded.lock().unwrap().push(patch["status"].clone());
                (
                    StatusCode::OK,
                    serde_json::to_value(subscription("s", None, "")).unwrap(),
                )
            }
        });

        deliver_one(
            &Api::namespaced(client.clone(), "prod"),
            &Api::namespaced(client, "prod"),
            // The URL is unroutable on purpose: a pass that never attempts must not touch it.
            &reqwest::Client::new(),
            &subscription("s", None, ""),
            3,
            DeliveryContext {
                repository: "fleet",
                namespace: "prod",
                prefix: "tenant/routing",
                public_url: "https://cdn.example/",
                version: 9,
                now: "2026-08-03T14:00:00Z",
            },
            std::time::Instant::now(),
        )
        .await;

        let recorded = recorded.lock().unwrap().clone();
        let [status] = recorded.as_slice() else {
            panic!("exactly one status write, got {recorded:?}");
        };
        assert_eq!(status["conditions"][0]["reason"], DEFERRED_REASON);
        assert_eq!(status["conditions"][0]["status"], "False");
        assert_eq!(status["deliveredVersions"]["fleet"], 3, "the mark stands");
        assert!(
            status.get("lastAttemptTime").is_none(),
            "a subscriber that got no attempt keeps its place in the fairness queue"
        );
    }

    #[tokio::test]
    async fn an_invalid_subscription_url_fails_closed_without_leaking_it_to_status() {
        use axum::http::{Method, StatusCode};
        let recorded: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let client = crate::tests::apiserver({
            let recorded = recorded.clone();
            move |_: &Method, _: &str, body: Vec<u8>| {
                let patch: serde_json::Value = serde_json::from_slice(&body).unwrap();
                recorded.lock().unwrap().push(patch["status"].clone());
                (
                    StatusCode::OK,
                    serde_json::to_value(subscription("s", None, "")).unwrap(),
                )
            }
        });
        let mut sub = subscription("s", None, "");
        sub.spec.webhook.url = "https://subscriber/hook?token=secret".into();

        deliver_one(
            &Api::namespaced(client.clone(), "prod"),
            &Api::namespaced(client, "prod"),
            &reqwest::Client::new(),
            &sub,
            0,
            DeliveryContext {
                repository: "fleet",
                namespace: "prod",
                prefix: "tenant/routing",
                public_url: "https://cdn.example/",
                version: 1,
                now: "2026-08-03T14:00:00Z",
            },
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await;

        let recorded = recorded.lock().unwrap();
        let [status] = recorded.as_slice() else {
            panic!("exactly one failure status, got {recorded:?}");
        };
        assert_eq!(status["conditions"][0]["reason"], FAILED_REASON);
        let message = status["conditions"][0]["message"].as_str().unwrap();
        assert!(message.contains("subscription webhook URL"), "{message}");
        assert!(!message.contains("secret"), "URL leaked in {message}");
        assert_eq!(status["deliveredVersions"]["fleet"], 0);
    }

    #[test]
    fn event_serializes_camel_case() {
        let event = UpdateEvent {
            repository: "fleet".into(),
            namespace: "prod".into(),
            prefix: "tenant/routing".into(),
            public_url: "https://cdn.example/".into(),
            version: 7,
            delivered_at: "2026-07-22T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["publicUrl"], "https://cdn.example/");
        assert_eq!(json["version"], 7);
        assert_eq!(json["deliveredAt"], "2026-07-22T00:00:00Z");
    }
}
