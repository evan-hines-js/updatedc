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

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::ResourceExt;
use serde::Serialize;

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

/// HMAC-SHA256 of `body` under `key`, lowercase hex — the value placed in `X-Updated-Signature`
/// (prefixed `sha256=`). The one crypto library, same backend as the gateway's mTLS.
fn sign_body(key: &[u8], body: &[u8]) -> String {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hex::encode(hmac::sign(&key, body).as_ref())
}

/// The HMAC signing key from a webhook's `secretRef` — the Secret's `key` entry.
async fn hmac_key(
    secrets: &Api<Secret>,
    name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret = secrets.get(name).await?;
    let bytes = secret
        .data
        .as_ref()
        .and_then(|data| data.get("key"))
        .ok_or_else(|| format!("webhook Secret {name} is missing entry 'key'"))?;
    Ok(bytes.0.clone())
}

/// Deliver pending update events to every subscription that covers `repository`, advancing each
/// subscription's per-repository high-water mark to `version` on success. Only apiserver failures
/// (listing subscriptions) are returned; a failed webhook `POST` is recorded in that subscription's
/// status and left for the next reconcile, so one broken subscriber never blocks the others or the
/// publish.
#[allow(clippy::too_many_arguments)]
pub async fn deliver_updates(
    subscriptions: &Api<UpdateSubscription>,
    secrets: &Api<Secret>,
    repository: &str,
    namespace: &str,
    prefix: &str,
    public_url: &str,
    version: u64,
    now: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Webhook URLs are operator-supplied (inside the CRD trust boundary), but refuse to follow
    // redirects so a webhook cannot bounce the signed event body to an internal-only endpoint
    // (cloud metadata, in-cluster services) that the configured host would not otherwise reach.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let deadline = std::time::Instant::now() + DELIVERY_BUDGET;
    for sub in subscriptions.list(&ListParams::default()).await? {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                repository,
                "subscription delivery budget spent; remaining subscribers resume next reconcile"
            );
            break;
        }
        if !covers(
            sub.spec.repository_ref.as_ref().map(|r| r.name.as_str()),
            repository,
        ) {
            continue;
        }
        let mark = sub
            .status
            .as_ref()
            .and_then(|status| status.delivered_versions.get(repository))
            .copied()
            .unwrap_or(0);
        if pending(mark, version).next().is_none() {
            continue;
        }
        deliver_one(
            subscriptions,
            secrets,
            &http,
            &sub,
            repository,
            namespace,
            prefix,
            public_url,
            mark,
            version,
            now,
            deadline,
        )
        .await;
    }
    Ok(())
}

/// Deliver pending generations to a single subscription, in order, stopping at the first failure —
/// and at [`MAX_EVENTS_PER_PASS`] or `deadline`, whichever comes first. The high-water mark and
/// status condition are written from whatever was actually acknowledged, so a bounded pass is
/// simply progress: the remainder resumes next reconcile.
#[allow(clippy::too_many_arguments)]
async fn deliver_one(
    subscriptions: &Api<UpdateSubscription>,
    secrets: &Api<Secret>,
    http: &reqwest::Client,
    sub: &UpdateSubscription,
    repository: &str,
    namespace: &str,
    prefix: &str,
    public_url: &str,
    mark: u64,
    version: u64,
    now: &str,
    deadline: std::time::Instant,
) {
    let name = sub.name_any();

    // Resolve the signing key once (if any) for the whole catch-up run.
    let key = match &sub.spec.webhook.secret_ref {
        Some(reference) => match hmac_key(secrets, &reference.name).await {
            Ok(key) => Some(key),
            Err(error) => {
                record(
                    subscriptions,
                    &name,
                    repository,
                    mark,
                    now,
                    None,
                    &format!("resolving webhook secret: {error}"),
                )
                .await;
                return;
            }
        },
        None => None,
    };

    let mut delivered = mark;
    for target in pending(mark, version).take(MAX_EVENTS_PER_PASS) {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let event = UpdateEvent {
            repository: repository.to_string(),
            namespace: namespace.to_string(),
            prefix: prefix.to_string(),
            public_url: public_url.to_string(),
            version: target,
            delivered_at: now.to_string(),
        };
        let body = match serde_json::to_vec(&event) {
            Ok(body) => body,
            Err(error) => {
                record(
                    subscriptions,
                    &name,
                    repository,
                    delivered,
                    now,
                    None,
                    &format!("encoding event: {error}"),
                )
                .await;
                return;
            }
        };
        let mut request = http
            .post(&sub.spec.webhook.url)
            .header("content-type", "application/json");
        if let Some(key) = &key {
            request = request.header(
                "x-updated-signature",
                format!("sha256={}", sign_body(key, &body)),
            );
        }
        match request.body(body).send().await {
            Ok(response) if response.status().is_success() => {
                delivered = target;
            }
            Ok(response) => {
                record(
                    subscriptions,
                    &name,
                    repository,
                    delivered,
                    now,
                    None,
                    &format!("webhook returned HTTP {}", response.status()),
                )
                .await;
                return;
            }
            Err(error) => {
                record(
                    subscriptions,
                    &name,
                    repository,
                    delivered,
                    now,
                    None,
                    &format!("posting to webhook: {error}"),
                )
                .await;
                return;
            }
        }
    }
    record(
        subscriptions,
        &name,
        repository,
        delivered,
        now,
        Some(now),
        "",
    )
    .await;
}

/// Persist a subscription's delivery progress: advance the per-repository mark to `delivered`, set a
/// `Ready` condition (`True` with `last_delivery` present on a clean run, `False` carrying `error`
/// otherwise), and stamp `last_delivery_time`. Best-effort — a failed status patch is logged, never
/// propagated, since delivery must not block the publish.
async fn record(
    subscriptions: &Api<UpdateSubscription>,
    name: &str,
    repository: &str,
    delivered: u64,
    now: &str,
    last_delivery: Option<&str>,
    error: &str,
) {
    let ready = error.is_empty();
    let condition = ResourceCondition {
        condition_type: "Ready".to_string(),
        status: if ready { "True" } else { "False" }.to_string(),
        reason: if ready { "Delivered" } else { "DeliveryFailed" }.to_string(),
        message: if ready {
            format!("delivered through generation {delivered}")
        } else {
            format!("stalled at generation {delivered}: {error}")
        },
        observed_generation: None,
        // Always stamped, including on the failure paths. An empty transition time is not a
        // "never" a reader can interpret — `kubectl` renders it as an epoch and any consumer
        // sorting conditions by age puts a fresh failure at the bottom.
        last_transition_time: now.to_string(),
    };
    let mut status = serde_json::json!({
        "deliveredVersions": { repository: delivered },
        "conditions": [condition],
    });
    if let Some(time) = last_delivery {
        status["lastDeliveryTime"] = serde_json::Value::String(time.to_string());
    }
    if let Err(error) = subscriptions
        .patch_status(
            name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await
    {
        tracing::warn!(subscription = name, error = %error, "recording subscription delivery status");
    }
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

    #[test]
    fn hmac_signature_is_stable_and_key_sensitive() {
        let body = br#"{"repository":"fleet","version":42}"#;
        let a = sign_body(b"secret-key", body);
        assert_eq!(
            a,
            sign_body(b"secret-key", body),
            "deterministic for a key+body"
        );
        assert_ne!(
            a,
            sign_body(b"other-key", body),
            "a different key changes the tag"
        );
        assert_ne!(
            a,
            sign_body(b"secret-key", b"tampered"),
            "a different body changes the tag"
        );
        assert_eq!(a.len(), 64, "SHA-256 tag is 32 bytes of hex");
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
