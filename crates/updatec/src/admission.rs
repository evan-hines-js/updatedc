//! Draupnir release admission.
//!
//! The webhook is deliberately both the event notification and the decision endpoint. Each POST
//! carries the complete active subject set, so delivery is idempotent and neither side has to make
//! an event stream agree with a separate query API. Responses preserve the authoritative
//! `nonCompliant` / `noInformation` distinction; reducing them to an allow-list would make the two
//! CRD actions impossible to apply correctly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use updated_contracts::key::P256PublicKey;

use k8s_openapi::api::core::v1::Secret;
use kube::Api;
use serde::{Deserialize, Serialize};

use crate::webhook::{hmac_key, signature, SIGNATURE_HEADER};
use crate::{
    AdmissionAction, AdmissionActions, AdmissionWebhookSpec, DesiredDeployment,
    UpdateAdmissionPolicy,
};

pub const ADMISSION_SCHEMA: u32 = 1;
/// The header carrying Draupnir's asymmetric signature over the exact response body bytes.
const DECISION_SIGNATURE_HEADER: &str = "x-draupnir-admission-signature";
/// The one algorithm this contract admits: ECDSA P-256 with SHA-256, ASN.1 DER signature, base64.
/// Named in the header so a future algorithm is a visible protocol change rather than a silent
/// reinterpretation of the same bytes.
const DECISION_SIGNATURE_ALGORITHM: &str = "es256";
const CACHE_TTL: Duration = Duration::from_secs(30);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 1024 * 1024;
const REVISION_LIMIT: usize = 256;
const REASON_LIMIT: usize = 1024;
const STATUS_MESSAGE_LIMIT: usize = 2048;
static HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    updated::http::outbound_client(updated::http::OutboundDeadline::Total(HTTP_TIMEOUT))
        .map_err(|error| format!("building admission HTTP client: {error}"))
});

/// The exact release facts Draupnir evaluates today. New policy-bearing manifest facts belong in
/// this typed object under a new protocol schema; arbitrary JSON would create an undocumented
/// second manifest API and make cache identities unstable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionSubject {
    /// SHA-256 of this canonical subject's policy-bearing facts.
    pub id: String,
    pub application_sha256: String,
}

impl AdmissionSubject {
    pub(crate) fn for_deployment(deployment: &DesiredDeployment) -> Self {
        // WIRE CONTRACT — these exact bytes are reproduced by the other side.
        //
        // Draupnir recomputes this digest on ingest and refuses any request whose subject id does
        // not bind its own facts, so a caller cannot present facts under someone else's id. That
        // makes this local-looking struct a cross-system contract: the serialization is the
        // agreement, not just an implementation detail.
        //
        // Consequently a change here is not a local edit. Adding, removing, renaming, or reordering
        // a field changes every subject id, and the receiving side rejects every request until it
        // is changed to match — which holds movement for the entire fleet, fail-closed and total.
        // Any change therefore requires a new `ADMISSION_SCHEMA` and a coordinated release of both
        // sides. `schema` is inside the digest precisely so that bump is unambiguous.
        //
        // Serialization specifics both sides depend on: serde_json compact (no spaces), camelCase
        // keys, declaration order, `schema` as a bare integer, and a lowercase-hex SHA-256.
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Facts<'a> {
            schema: u32,
            application_sha256: &'a str,
        }

        let facts = Facts {
            schema: ADMISSION_SCHEMA,
            application_sha256: &deployment.application.sha256,
        };
        let encoded = serde_json::to_vec(&facts).expect("admission facts contain only strings");
        Self {
            id: updated_contracts::digest::sha256_bytes(&encoded),
            application_sha256: deployment.application.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionRequest {
    pub schema: u32,
    /// Fresh 256-bit nonce binding the response to this exchange.
    pub request_id: String,
    pub namespace: String,
    pub repository: String,
    pub subjects: Vec<AdmissionSubject>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AdmissionVerdict {
    Compliant,
    NonCompliant,
    NoInformation,
    Pending,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectDecision {
    pub subject_id: String,
    pub verdict: AdmissionVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionResponse {
    pub schema: u32,
    /// Exact nonce from the request. It prevents replay of an older signed decision set.
    pub request_id: String,
    /// Draupnir's opaque decision-set revision, surfaced for diagnosis and audit correlation.
    pub revision: String,
    pub decisions: Vec<SubjectDecision>,
}

/// Where a policy's decisions come from, and the two independent credentials one round trip needs:
/// the shared secret that proves which caller is asking, and the pinned public key whose signature
/// an answer must carry. They travel together because pairing a URL with the wrong key is exactly
/// the mistake that separate parameters invite.
struct AdmissionEndpoint<'a> {
    url: &'a str,
    /// HMAC key authenticating the request bytes. Caller authentication only.
    request_key: &'a [u8],
    /// Draupnir's pinned public key, as an uncompressed P-256 point.
    decision_key: &'a P256PublicKey,
}

/// Stable facts used for cache identity. The per-exchange nonce is deliberately absent and is
/// minted only when a network refresh is actually required.
struct AdmissionQuery {
    namespace: String,
    repository: String,
    subjects: Vec<AdmissionSubject>,
}

#[derive(Clone, Debug)]
struct CachedDecisionSet {
    policy: String,
    fingerprint: String,
    fetched_at: Instant,
    revision: String,
    decisions: BTreeMap<String, SubjectDecision>,
}

#[derive(Clone, Debug)]
struct FailedAttempt {
    policy: String,
    fingerprint: String,
    attempted_at: Instant,
    requested: BTreeSet<String>,
    error: String,
}

/// One bounded cache for the one policy a repository can reference. Replacing the reference
/// replaces this entry; policy churn therefore cannot grow controller memory without bound.
#[derive(Default)]
pub(crate) struct AdmissionCache {
    entry: Option<CachedDecisionSet>,
    failed: Option<FailedAttempt>,
}

impl AdmissionCache {
    pub(crate) fn clear(&mut self) {
        self.entry = None;
        self.failed = None;
    }

    async fn decisions(
        &mut self,
        policy_name: &str,
        fingerprint: &str,
        endpoint: &AdmissionEndpoint<'_>,
        query: &AdmissionQuery,
        now: Instant,
    ) -> (
        BTreeMap<String, SubjectDecision>,
        Option<String>,
        Option<String>,
    ) {
        let expected: BTreeSet<String> = query
            .subjects
            .iter()
            .map(|subject| subject.id.clone())
            .collect();
        let fresh = self.entry.as_ref().filter(|cached| {
            cached.policy == policy_name
                && cached.fingerprint == fingerprint
                && now.saturating_duration_since(cached.fetched_at) < CACHE_TTL
        });
        if let Some(cached) = fresh.filter(|cached| {
            expected
                .iter()
                .all(|subject| cached.decisions.contains_key(subject))
        }) {
            return (
                select_decisions(&cached.decisions, &expected),
                Some(cached.revision.clone()),
                None,
            );
        }
        // A failed endpoint must not be hammered once per one-second reconcile. The attempted set
        // is cached for the same 30-second cadence; a genuinely new subject still bypasses it and
        // triggers the immediate event/refresh required by the protocol.
        if let Some(failed) = self.failed.as_ref().filter(|failed| {
            failed.policy == policy_name
                && failed.fingerprint == fingerprint
                && now.saturating_duration_since(failed.attempted_at) < CACHE_TTL
                && expected.is_subset(&failed.requested)
        }) {
            let fallback = fresh
                .map(|cached| select_decisions(&cached.decisions, &expected))
                .unwrap_or_default();
            let revision = fresh.map(|cached| cached.revision.clone());
            return (fallback, revision, Some(failed.error.clone()));
        }

        let fetched = match updated::rand::token() {
            Ok(request_id) => {
                fetch(
                    endpoint,
                    &AdmissionRequest {
                        schema: ADMISSION_SCHEMA,
                        request_id,
                        namespace: query.namespace.clone(),
                        repository: query.repository.clone(),
                        subjects: query.subjects.clone(),
                    },
                )
                .await
            }
            Err(error) => Err(format!("generating admission request ID: {error}")),
        };
        match fetched {
            Ok(response) => {
                let decisions: BTreeMap<String, SubjectDecision> = response
                    .decisions
                    .into_iter()
                    .map(|decision| (decision.subject_id.clone(), decision))
                    .collect();
                let revision = response.revision;
                self.entry = Some(CachedDecisionSet {
                    policy: policy_name.to_string(),
                    fingerprint: fingerprint.to_string(),
                    fetched_at: now,
                    revision: revision.clone(),
                    decisions: decisions.clone(),
                });
                self.failed = None;
                (decisions, Some(revision), None)
            }
            Err(error) => {
                // A new subject forces a refresh, but it does not invalidate still-fresh decisions
                // for known subjects. The unseen subject is absent below and therefore held; once
                // the 30-second deadline passes, every old decision is absent and held.
                let fallback = fresh
                    .map(|cached| select_decisions(&cached.decisions, &expected))
                    .unwrap_or_default();
                let revision = fresh.map(|cached| cached.revision.clone());
                self.failed = Some(FailedAttempt {
                    policy: policy_name.to_string(),
                    fingerprint: fingerprint.to_string(),
                    attempted_at: now,
                    requested: expected,
                    error: error.clone(),
                });
                (fallback, revision, Some(error))
            }
        }
    }
}

fn select_decisions(
    decisions: &BTreeMap<String, SubjectDecision>,
    expected: &BTreeSet<String>,
) -> BTreeMap<String, SubjectDecision> {
    expected
        .iter()
        .filter_map(|id| {
            decisions
                .get(id)
                .map(|decision| (id.clone(), decision.clone()))
        })
        .collect()
}

/// The one effective admission verdict for a reconcile pass. All rollout paths ask this object;
/// transport failures and incomplete responses are never reclassified as `noInformation`.
#[derive(Clone, Debug)]
pub(crate) struct AdmissionEvaluation {
    pub(crate) policy_name: Option<String>,
    pub(crate) revision: Option<String>,
    pub(crate) error: Option<String>,
    actions: Option<AdmissionActions>,
    decisions: BTreeMap<String, SubjectDecision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionStatus {
    pub(crate) allowed: bool,
    pub(crate) reason: &'static str,
    pub(crate) message: String,
}

impl AdmissionEvaluation {
    pub(crate) fn disabled() -> Self {
        Self {
            policy_name: None,
            revision: None,
            error: None,
            actions: None,
            decisions: BTreeMap::new(),
        }
    }

    fn unavailable(policy_name: String, error: impl Into<String>) -> Self {
        Self {
            policy_name: Some(policy_name),
            revision: None,
            error: Some(error.into()),
            actions: None,
            decisions: BTreeMap::new(),
        }
    }

    /// The one interpretation of a policy verdict. Planning acts on `allowed`, and status projects
    /// the rest of this same value; there is no second boolean decision path that can drift from
    /// what operators see.
    pub(crate) fn status(&self, deployment: &DesiredDeployment) -> Option<AdmissionStatus> {
        let policy = self.policy_name.as_deref()?;
        let subject = AdmissionSubject::for_deployment(deployment);
        let revision = self.revision.as_deref().unwrap_or("unavailable");
        let Some(actions) = self.actions else {
            return Some(AdmissionStatus {
                allowed: false,
                reason: "AdmissionUnavailable",
                message: status_message(format!(
                    "UpdateAdmissionPolicy {policy} cannot be evaluated for subject {}; {}",
                    subject.id,
                    self.error
                        .as_deref()
                        .unwrap_or("no authoritative decision is available")
                )),
            });
        };
        let Some(decision) = self.decisions.get(&subject.id) else {
            return Some(AdmissionStatus {
                allowed: false,
                reason: "AdmissionUnavailable",
                message: status_message(format!(
                    "UpdateAdmissionPolicy {policy} has no current authoritative decision for subject {} (last revision {revision}); {}",
                    subject.id,
                    self.error.as_deref().unwrap_or("the response was incomplete")
                )),
            });
        };
        let detail = decision.reason.as_deref().unwrap_or("no detail supplied");
        let (allowed, reason, action) = match decision.verdict {
            AdmissionVerdict::Compliant => (true, "Compliant", "allows"),
            AdmissionVerdict::NonCompliant if actions.non_compliant == AdmissionAction::Allow => {
                (true, "NonCompliantAllowed", "allows")
            }
            AdmissionVerdict::NonCompliant => (false, "NonCompliantBlocked", "blocks"),
            AdmissionVerdict::NoInformation if actions.no_information == AdmissionAction::Allow => {
                (true, "NoInformationAllowed", "allows")
            }
            AdmissionVerdict::NoInformation => (false, "NoInformationBlocked", "blocks"),
            AdmissionVerdict::Pending => (false, "DecisionPending", "blocks"),
        };
        Some(AdmissionStatus {
            allowed,
            reason,
            message: status_message(format!(
                "UpdateAdmissionPolicy {policy} {action} subject {} at Draupnir revision {revision}: {detail}",
                subject.id
            )),
        })
    }
}

/// The pinned decision key, decoded and shape-checked once before any request is sent.
///
/// A malformed pin is refused here rather than at verification time: reaching the verifier, it
/// would fail every signature and be indistinguishable in the logs from Draupnir forging or a
/// tampered response. [`P256PublicKey`] is the same gate every other pinned key in this system is
/// admitted through, so the boundary check and the verification cannot drift.
fn decision_public_key(encoded: &str) -> Result<P256PublicKey, String> {
    P256PublicKey::parse_hex(encoded.trim()).map_err(|error| format!("decisionPublicKey {error}"))
}

/// Verify Draupnir's signature over the EXACT bytes received.
///
/// The bytes verified here are the bytes decoded into the decision set, so the signed document and
/// the enforced document are the same document. Verifying a re-serialization instead would let the
/// two drift the first time a field ordering or an escape changed, and would break the binding
/// Draupnir's retained attestation depends on.
fn verify_decision_signature(public_key: &P256PublicKey, body: &[u8], header: &str) -> bool {
    use base64::Engine as _;

    let Some(encoded) = header
        .trim()
        .strip_prefix(DECISION_SIGNATURE_ALGORITHM)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return false;
    };
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    public_key.verify_asn1(body, &signature)
}

fn status_message(mut message: String) -> String {
    if message.len() <= STATUS_MESSAGE_LIMIT {
        return message;
    }
    let mut end = STATUS_MESSAGE_LIMIT.saturating_sub(3);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message.truncate(end);
    message.push_str("...");
    message
}

/// Identity of the remote authority behind a cached decision set. Local action changes are
/// deliberately absent: they reinterpret the same still-current authoritative verdict
/// immediately, without turning a CRD edit into an extra webhook call. Context and credential
/// changes are present so a cache entry can never cross repositories or survive endpoint/key
/// rotation.
fn cache_fingerprint(
    webhook: &AdmissionWebhookSpec,
    request_key: &[u8],
    namespace: &str,
    repository: &str,
) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Identity<'a> {
        schema: u32,
        namespace: &'a str,
        repository: &'a str,
        webhook: &'a AdmissionWebhookSpec,
        request_key_sha256: String,
    }

    let identity = Identity {
        schema: ADMISSION_SCHEMA,
        namespace,
        repository,
        webhook,
        request_key_sha256: updated_contracts::digest::sha256_bytes(request_key),
    };
    updated_contracts::digest::sha256_bytes(
        &serde_json::to_vec(&identity).expect("admission cache identity always serializes"),
    )
}

/// Resolve the referenced policy and its signing key, then refresh or read the 30-second cache.
/// Any configured-path failure returns a fail-closed evaluation rather than failing the whole
/// reconcile: existing assignments can still be republished while movement is held.
pub(crate) async fn evaluate(
    cache: &mut AdmissionCache,
    policies: &Api<UpdateAdmissionPolicy>,
    secrets: &Api<Secret>,
    policy_ref: Option<&str>,
    namespace: &str,
    repository: &str,
    deployments: impl Iterator<Item = &DesiredDeployment>,
) -> AdmissionEvaluation {
    let Some(policy_name) = policy_ref else {
        cache.clear();
        return AdmissionEvaluation::disabled();
    };
    let subjects: BTreeMap<String, AdmissionSubject> = deployments
        .map(AdmissionSubject::for_deployment)
        .map(|subject| (subject.id.clone(), subject))
        .collect();
    let policy = match policies.get(policy_name).await {
        Ok(policy) => policy,
        Err(error) => {
            return AdmissionEvaluation::unavailable(
                policy_name.to_string(),
                format!("reading UpdateAdmissionPolicy: {error}"),
            );
        }
    };
    // The pinned decision key is validated before the request is sent, not after the response
    // arrives: a policy whose pin cannot verify anything must hold movement rather than issue a
    // call whose answer it could never trust.
    let decision_key = match decision_public_key(&policy.spec.webhook.decision_public_key) {
        Ok(point) => point,
        Err(error) => {
            return AdmissionEvaluation {
                policy_name: Some(policy_name.to_string()),
                revision: None,
                error: Some(format!("reading admission decision key: {error}")),
                actions: Some(policy.spec.actions),
                decisions: BTreeMap::new(),
            };
        }
    };
    let key = match hmac_key(secrets, &policy.spec.webhook.secret_ref.name).await {
        Ok(key) => key,
        Err(error) => {
            return AdmissionEvaluation {
                policy_name: Some(policy_name.to_string()),
                revision: None,
                error: Some(format!("reading admission webhook key: {error}")),
                actions: Some(policy.spec.actions),
                decisions: BTreeMap::new(),
            };
        }
    };
    let query = AdmissionQuery {
        namespace: namespace.to_string(),
        repository: repository.to_string(),
        subjects: subjects.into_values().collect(),
    };
    let fingerprint = cache_fingerprint(&policy.spec.webhook, &key, namespace, repository);
    let (decisions, revision, error) = cache
        .decisions(
            policy_name,
            &fingerprint,
            &AdmissionEndpoint {
                url: &policy.spec.webhook.url,
                request_key: &key,
                decision_key: &decision_key,
            },
            &query,
            Instant::now(),
        )
        .await;
    AdmissionEvaluation {
        policy_name: Some(policy_name.to_string()),
        revision,
        error,
        actions: Some(policy.spec.actions),
        decisions,
    }
}

/// One admission round trip. The two directions authenticate differently and deliberately so:
/// the REQUEST proves which caller is asking (HMAC, a shared secret, symmetric because both ends
/// may legitimately produce it), while the RESPONSE is an authoritative compliance assertion that
/// gates deployment and is therefore signed by Draupnir alone, verified here against a pinned
/// public key this control plane cannot sign with.
async fn fetch(
    endpoint: &AdmissionEndpoint<'_>,
    request: &AdmissionRequest,
) -> Result<AdmissionResponse, String> {
    let body = serde_json::to_vec(request).map_err(|error| format!("encoding request: {error}"))?;
    if body.len() > BODY_LIMIT {
        return Err(format!(
            "admission request is larger than the {BODY_LIMIT}-byte limit"
        ));
    }
    let url = updated::http::network_endpoint(
        endpoint.url,
        updated::http::EndpointTransport::HttpOrHttps,
        "admission webhook URL",
    )
    .map_err(|error| error.to_string())?;
    let client = HTTP_CLIENT.as_ref().map_err(Clone::clone)?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header(SIGNATURE_HEADER, signature(endpoint.request_key, &body))
        .body(body)
        .send()
        .await
        .map_err(|error| {
            updated::http::redacted_reqwest_error("calling admission webhook", &error).to_string()
        })?;
    let status = response.status();
    if !status.is_success() {
        // An HTTP error is transport failure, never a semantic verdict. Refuse it before looking
        // for a signature so even a signed JSON error document cannot accidentally become an
        // authoritative decision after an endpoint or proxy misconfiguration.
        return Err(format!("admission webhook returned HTTP {status}"));
    }
    let response_signature = response
        .headers()
        .get(DECISION_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| format!("admission response is missing {DECISION_SIGNATURE_HEADER}"))?;
    let body = updated::http::read_bounded(response, "admission webhook", BODY_LIMIT)
        .await
        .map_err(|error| error.to_string())?;
    // Verified against the bytes as received, before they are parsed — so what is authenticated is
    // exactly what is acted on, and an unverified body never reaches the decoder.
    if !verify_decision_signature(endpoint.decision_key, &body, &response_signature) {
        return Err("admission decision signature is invalid".into());
    }
    let response: AdmissionResponse = serde_json::from_slice(&body)
        .map_err(|error| format!("decoding admission response: {error}"))?;
    validate_response(request, &response)?;
    Ok(response)
}

fn validate_response(
    request: &AdmissionRequest,
    response: &AdmissionResponse,
) -> Result<(), String> {
    if response.schema != ADMISSION_SCHEMA {
        return Err(format!(
            "unsupported admission response schema {} (expected {ADMISSION_SCHEMA})",
            response.schema
        ));
    }
    if response.request_id != request.request_id {
        return Err("admission response requestId does not match the request".into());
    }
    if response.revision.is_empty() || response.revision.len() > REVISION_LIMIT {
        return Err(format!(
            "admission response revision must be 1..={REVISION_LIMIT} bytes"
        ));
    }
    let expected: BTreeSet<&str> = request
        .subjects
        .iter()
        .map(|subject| subject.id.as_str())
        .collect();
    let mut actual = BTreeSet::new();
    for decision in &response.decisions {
        if decision
            .reason
            .as_ref()
            .is_some_and(|reason| reason.len() > REASON_LIMIT)
        {
            return Err(format!(
                "admission response reason for subject {} is larger than the {REASON_LIMIT}-byte limit",
                decision.subject_id
            ));
        }
        if !actual.insert(decision.subject_id.as_str()) {
            return Err(format!(
                "admission response repeats subject {}",
                decision.subject_id
            ));
        }
        if !expected.contains(decision.subject_id.as_str()) {
            return Err(format!(
                "admission response contains unrequested subject {}",
                decision.subject_id
            ));
        }
    }
    if actual != expected {
        return Err(format!(
            "admission response omits {} requested subject(s)",
            expected.difference(&actual).count(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// A throwaway Draupnir admission key. Tests sign the exact response bytes with it and pin its
    /// public point, so they exercise the real ECDSA path rather than a stubbed verifier — the
    /// whole point of the change is that only the holder of this key can produce a verdict.
    struct DecisionKey {
        key: aws_lc_rs::signature::EcdsaKeyPair,
        point: P256PublicKey,
    }

    impl DecisionKey {
        fn new() -> Self {
            use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            let point = P256PublicKey::from_point(key.public_key().as_ref()).unwrap();
            Self { key, point }
        }

        /// The header value Draupnir sends: the algorithm it signed with, then the DER signature.
        fn header(&self, body: &[u8]) -> String {
            use base64::Engine as _;

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let signature = self.key.sign(&rng, body).unwrap();
            format!(
                "{DECISION_SIGNATURE_ALGORITHM}:{}",
                base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
            )
        }

        fn pin(&self) -> String {
            self.point.to_hex()
        }
    }

    /// One key for the whole test module, so the nested axum handlers below can reach it without
    /// threading state through every fixture.
    static DECISION_KEY: LazyLock<DecisionKey> = LazyLock::new(DecisionKey::new);

    /// The endpoint under test: the fixture's URL, an arbitrary request key, and the one pinned
    /// decision key every fixture's responses are signed with.
    fn endpoint(url: &str) -> AdmissionEndpoint<'_> {
        AdmissionEndpoint {
            url,
            request_key: b"key",
            decision_key: &DECISION_KEY.point,
        }
    }

    /// The property the whole asymmetric change exists for: only the holder of Draupnir's private
    /// key can produce a verdict this control plane will act on. Every other case is a refusal,
    /// because a decision that fails to verify has no safe reading.
    #[test]
    fn only_draupnirs_key_over_these_exact_bytes_yields_a_verdict() {
        let body = br#"{"schema":1,"revision":"r1","decisions":[]}"#;
        let signed = DECISION_KEY.header(body);
        assert!(verify_decision_signature(
            &DECISION_KEY.point,
            body,
            &signed
        ));

        // A different key: an impostor endpoint, or this control plane trying to mint its own
        // verdict. It holds no private key that verifies against the pin, which is the point.
        let impostor = DecisionKey::new();
        assert!(!verify_decision_signature(
            &DECISION_KEY.point,
            body,
            &impostor.header(body)
        ));
        assert!(!verify_decision_signature(&impostor.point, body, &signed));

        // The signature covers the exact bytes, so any edit to the body invalidates it. This is
        // what keeps the signed document and the enforced document the same document.
        assert!(!verify_decision_signature(
            &DECISION_KEY.point,
            br#"{"schema":1,"revision":"r2","decisions":[]}"#,
            &signed
        ));

        // Malformed headers are refusals, never accidental acceptance.
        for header in [
            "",
            "es256:",
            "es256:not-base64!!",
            "sha256=deadbeef",
            &signed.replace("es256:", ""),
            // A real signature under an algorithm label this contract does not admit: the label is
            // part of what is agreed, so reinterpreting the bytes under it is not allowed.
            &signed.replace("es256", "es384"),
        ] {
            assert!(
                !verify_decision_signature(&DECISION_KEY.point, body, header),
                "accepted malformed decision signature header {header:?}"
            );
        }
    }

    /// A pin that cannot verify anything must be refused before a request is ever sent. Reaching
    /// the verifier, it would fail every signature and look exactly like Draupnir being forged.
    #[test]
    fn a_malformed_pin_is_refused_at_the_boundary() {
        assert_eq!(
            decision_public_key(&DECISION_KEY.pin()).unwrap(),
            DECISION_KEY.point
        );
        for pin in [
            "",
            "not-hex",
            // Right length, wrong form: a compressed point.
            &format!("02{}", "ab".repeat(32)),
            // Right length and prefix, but not a point on P-256. Shape checking alone accepts it;
            // the curve-membership check must not.
            &format!("04{}", "00".repeat(64)),
            // Truncated by one byte.
            &hex::encode(&DECISION_KEY.point.as_bytes()[..64]),
            // A PEM/SPKI key pasted in place of the raw point — the mistake operator config makes.
            &hex::encode("-----BEGIN PUBLIC KEY-----"),
            // Correct length and SEC1 prefix, but not a point on the curve.
            &format!("04{}", "ab".repeat(64)),
            // The right key in the wrong spelling: one key must not have two names.
            &DECISION_KEY.pin().to_uppercase(),
        ] {
            assert!(
                decision_public_key(pin).is_err(),
                "accepted malformed decisionPublicKey {pin:?}"
            );
        }
    }

    fn actions(
        non_compliant: AdmissionAction,
        no_information: AdmissionAction,
    ) -> AdmissionActions {
        AdmissionActions {
            non_compliant,
            no_information,
        }
    }

    fn evaluation(
        deployment: &DesiredDeployment,
        verdict: AdmissionVerdict,
        actions: AdmissionActions,
    ) -> AdmissionEvaluation {
        let subject = AdmissionSubject::for_deployment(deployment);
        AdmissionEvaluation {
            policy_name: Some("draupnir".into()),
            revision: Some("r1".into()),
            error: None,
            actions: Some(actions),
            decisions: BTreeMap::from([(
                subject.id.clone(),
                SubjectDecision {
                    subject_id: subject.id,
                    verdict,
                    reason: None,
                },
            )]),
        }
    }

    #[test]
    fn noncompliant_and_no_information_actions_are_independent() {
        let deployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let policy = actions(AdmissionAction::Block, AdmissionAction::Allow);
        assert!(
            !evaluation(&deployment, AdmissionVerdict::NonCompliant, policy)
                .status(&deployment)
                .unwrap()
                .allowed
        );
        assert!(
            evaluation(&deployment, AdmissionVerdict::NoInformation, policy)
                .status(&deployment)
                .unwrap()
                .allowed
        );

        let inverse = actions(AdmissionAction::Allow, AdmissionAction::Block);
        assert!(
            evaluation(&deployment, AdmissionVerdict::NonCompliant, inverse)
                .status(&deployment)
                .unwrap()
                .allowed
        );
        assert!(
            !evaluation(&deployment, AdmissionVerdict::NoInformation, inverse)
                .status(&deployment)
                .unwrap()
                .allowed
        );
    }

    #[test]
    fn uncertainty_always_blocks_and_disabled_never_does() {
        let deployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let allow = actions(AdmissionAction::Allow, AdmissionAction::Allow);
        assert!(
            !evaluation(&deployment, AdmissionVerdict::Pending, allow)
                .status(&deployment)
                .unwrap()
                .allowed
        );
        assert!(
            !AdmissionEvaluation {
                policy_name: Some("draupnir".into()),
                revision: None,
                error: Some("down".into()),
                actions: Some(allow),
                decisions: BTreeMap::new(),
            }
            .status(&deployment)
            .unwrap()
            .allowed
        );
        assert!(AdmissionEvaluation::disabled()
            .status(&deployment)
            .is_none());
    }

    #[test]
    fn response_must_cover_exactly_the_requested_subjects_once() {
        let deployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let subject = AdmissionSubject::for_deployment(&deployment);
        let request = AdmissionRequest {
            schema: ADMISSION_SCHEMA,
            request_id: "request-1".into(),
            namespace: "ns".into(),
            repository: "repo".into(),
            subjects: vec![subject.clone()],
        };
        let valid = SubjectDecision {
            subject_id: subject.id.clone(),
            verdict: AdmissionVerdict::Compliant,
            reason: None,
        };
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id.clone(),
                revision: "r1".into(),
                decisions: vec![valid.clone()],
            }
        )
        .is_ok());
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id.clone(),
                revision: "r1".into(),
                decisions: vec![],
            }
        )
        .unwrap_err()
        .contains("omits"));
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id.clone(),
                revision: "r1".into(),
                decisions: vec![valid.clone(), valid.clone()],
            }
        )
        .unwrap_err()
        .contains("repeats"));

        let mut oversized_reason = valid;
        oversized_reason.reason = Some("x".repeat(REASON_LIMIT + 1));
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id.clone(),
                revision: "r1".into(),
                decisions: vec![oversized_reason],
            }
        )
        .unwrap_err()
        .contains("reason"));
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id.clone(),
                revision: "r".repeat(REVISION_LIMIT + 1),
                decisions: vec![],
            }
        )
        .unwrap_err()
        .contains("revision"));
        assert!(validate_response(
            &request,
            &AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: "captured-older-request".into(),
                revision: "r1".into(),
                decisions: vec![SubjectDecision {
                    subject_id: subject.id,
                    verdict: AdmissionVerdict::Compliant,
                    reason: None,
                }],
            }
        )
        .unwrap_err()
        .contains("requestId"));
    }

    #[test]
    fn status_messages_are_bounded_without_splitting_utf8() {
        let message = status_message("🙂".repeat(STATUS_MESSAGE_LIMIT));
        assert!(message.len() <= STATUS_MESSAGE_LIMIT);
        assert!(message.ends_with("..."));
    }

    #[tokio::test]
    async fn cache_refreshes_at_thirty_seconds_and_immediately_for_a_new_subject() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use axum::extract::State;
        use axum::http::{HeaderMap, HeaderValue};
        use axum::routing::post;
        use axum::{Json, Router};

        async fn decide(
            State(calls): State<Arc<AtomicUsize>>,
            Json(request): Json<AdmissionRequest>,
        ) -> (HeaderMap, Vec<u8>) {
            let revision = calls.fetch_add(1, Ordering::SeqCst) + 1;
            let response = AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id,
                revision: format!("r{revision}"),
                decisions: request
                    .subjects
                    .into_iter()
                    .map(|subject| SubjectDecision {
                        subject_id: subject.id,
                        verdict: AdmissionVerdict::Compliant,
                        reason: None,
                    })
                    .collect(),
            };
            let body = serde_json::to_vec(&response).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                DECISION_SIGNATURE_HEADER,
                HeaderValue::from_str(&DECISION_KEY.header(&body)).unwrap(),
            );
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            (headers, body)
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/decide", post(decide))
            .with_state(calls.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let mut first: DesiredDeployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let first_subject = AdmissionSubject::for_deployment(&first);
        let mut query = AdmissionQuery {
            namespace: "ns".into(),
            repository: "repo".into(),
            subjects: vec![first_subject],
        };
        let url = format!("http://{address}/decide");
        let start = Instant::now();
        let mut cache = AdmissionCache::default();
        cache
            .decisions("draupnir", "p1", &endpoint(&url), &query, start)
            .await;
        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(29),
            )
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh complete set is reused"
        );

        first.application.sha256 = "3".repeat(64);
        query
            .subjects
            .push(AdmissionSubject::for_deployment(&first));
        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(29),
            )
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a new subject refreshes immediately"
        );

        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(59),
            )
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the 30-second boundary refreshes"
        );
        server.abort();
    }

    #[tokio::test]
    async fn failed_refresh_is_rate_limited_but_a_new_subject_still_notifies() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::routing::post;
        use axum::Router;

        async fn unavailable(State(calls): State<Arc<AtomicUsize>>) -> StatusCode {
            calls.fetch_add(1, Ordering::SeqCst);
            StatusCode::SERVICE_UNAVAILABLE
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/decide", post(unavailable))
            .with_state(calls.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let mut deployment: DesiredDeployment =
            crate::tests::deployment_spec("v1").try_into().unwrap();
        let mut query = AdmissionQuery {
            namespace: "ns".into(),
            repository: "repo".into(),
            subjects: vec![AdmissionSubject::for_deployment(&deployment)],
        };
        let url = format!("http://{address}/decide");
        let start = Instant::now();
        let mut cache = AdmissionCache::default();
        cache
            .decisions("draupnir", "p1", &endpoint(&url), &query, start)
            .await;
        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(1),
            )
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        deployment.application.sha256 = "4".repeat(64);
        query
            .subjects
            .push(AdmissionSubject::for_deployment(&deployment));
        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(1),
            )
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        cache
            .decisions(
                "draupnir",
                "p1",
                &endpoint(&url),
                &query,
                start + Duration::from_secs(31),
            )
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        server.abort();
    }

    #[tokio::test]
    async fn referenced_crd_and_secret_drive_the_authoritative_action() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use axum::extract::State;
        use axum::http::{HeaderMap, HeaderValue};
        use axum::routing::post;
        use axum::{Json, Router};
        use k8s_openapi::ByteString;

        async fn decide(
            State(calls): State<Arc<AtomicUsize>>,
            Json(request): Json<AdmissionRequest>,
        ) -> (HeaderMap, Vec<u8>) {
            calls.fetch_add(1, Ordering::SeqCst);
            let response = AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id,
                revision: "policy-7".into(),
                decisions: request
                    .subjects
                    .into_iter()
                    .map(|subject| SubjectDecision {
                        subject_id: subject.id,
                        verdict: AdmissionVerdict::NonCompliant,
                        reason: Some("known finding".into()),
                    })
                    .collect(),
            };
            let body = serde_json::to_vec(&response).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                DECISION_SIGNATURE_HEADER,
                HeaderValue::from_str(&DECISION_KEY.header(&body)).unwrap(),
            );
            (headers, body)
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/decide", post(decide))
            .with_state(calls.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut policy = UpdateAdmissionPolicy::new(
            "draupnir",
            crate::UpdateAdmissionPolicySpec {
                webhook: crate::AdmissionWebhookSpec {
                    url: format!("http://{address}/decide"),
                    secret_ref: crate::LocalSecretReference { name: "key".into() },
                    decision_public_key: DECISION_KEY.pin(),
                },
                actions: actions(AdmissionAction::Allow, AdmissionAction::Block),
            },
        );
        policy.metadata.resource_version = Some("12".into());
        let secret = Secret {
            metadata: kube::api::ObjectMeta {
                name: Some("key".into()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                "key".into(),
                ByteString(b"0123456789abcdef0123456789abcdef".to_vec()),
            )])),
            ..Default::default()
        };
        let policy_json = Arc::new(Mutex::new(serde_json::to_value(&policy).unwrap()));
        let secret_json = serde_json::to_value(secret).unwrap();
        let served_policy = policy_json.clone();
        let client = crate::tests::apiserver(move |_, path, _| {
            if path.contains("updateadmissionpolicies") {
                (
                    axum::http::StatusCode::OK,
                    served_policy.lock().unwrap().clone(),
                )
            } else {
                (axum::http::StatusCode::OK, secret_json.clone())
            }
        });
        let policies: Api<UpdateAdmissionPolicy> = Api::namespaced(client.clone(), "ns");
        let secrets: Api<Secret> = Api::namespaced(client, "ns");
        let deployment: DesiredDeployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let mut cache = AdmissionCache::default();
        let evaluated = evaluate(
            &mut cache,
            &policies,
            &secrets,
            Some("draupnir"),
            "ns",
            "repo",
            std::iter::once(&deployment),
        )
        .await;
        assert_eq!(evaluated.revision.as_deref(), Some("policy-7"));
        let status = evaluated.status(&deployment).unwrap();
        assert!(
            status.allowed,
            "the CRD explicitly allows a nonCompliant verdict"
        );
        assert_eq!(status.reason, "NonCompliantAllowed");

        // Actions are local interpretation, not remote authority. An operator edit converges to the
        // cached signed verdict immediately and must not manufacture a second webhook refresh.
        policy.spec.actions.non_compliant = AdmissionAction::Block;
        policy.metadata.resource_version = Some("13".into());
        *policy_json.lock().unwrap() = serde_json::to_value(policy).unwrap();
        let reevaluated = evaluate(
            &mut cache,
            &policies,
            &secrets,
            Some("draupnir"),
            "ns",
            "repo",
            std::iter::once(&deployment),
        )
        .await;
        let status = reevaluated.status(&deployment).unwrap();
        assert!(!status.allowed);
        assert_eq!(status.reason, "NonCompliantBlocked");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "changing only CRD actions reuses the still-current signed decision set"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_signed_non_success_response_is_still_transport_failure() {
        use axum::http::{HeaderMap, HeaderValue, StatusCode};
        use axum::routing::post;
        use axum::{Json, Router};

        async fn unavailable(
            Json(request): Json<AdmissionRequest>,
        ) -> (StatusCode, HeaderMap, Vec<u8>) {
            let response = AdmissionResponse {
                schema: ADMISSION_SCHEMA,
                request_id: request.request_id,
                revision: "r1".into(),
                decisions: request
                    .subjects
                    .into_iter()
                    .map(|subject| SubjectDecision {
                        subject_id: subject.id,
                        verdict: AdmissionVerdict::Compliant,
                        reason: None,
                    })
                    .collect(),
            };
            let body = serde_json::to_vec(&response).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                DECISION_SIGNATURE_HEADER,
                HeaderValue::from_str(&DECISION_KEY.header(&body)).unwrap(),
            );
            (StatusCode::SERVICE_UNAVAILABLE, headers, body)
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/decide", post(unavailable)))
                .await
                .unwrap()
        });
        let deployment: DesiredDeployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let request = AdmissionRequest {
            schema: ADMISSION_SCHEMA,
            request_id: "1".repeat(64),
            namespace: "ns".into(),
            repository: "repo".into(),
            subjects: vec![AdmissionSubject::for_deployment(&deployment)],
        };
        let error = fetch(&endpoint(&format!("http://{address}/decide")), &request)
            .await
            .expect_err("a signed HTTP error must never be interpreted as a verdict");
        assert!(error.contains("503 Service Unavailable"), "{error}");
        server.abort();
    }

    #[tokio::test]
    async fn admission_rejects_url_credentials_before_any_request() {
        let deployment: DesiredDeployment = crate::tests::deployment_spec("v1").try_into().unwrap();
        let request = AdmissionRequest {
            schema: ADMISSION_SCHEMA,
            request_id: "1".repeat(64),
            namespace: "ns".into(),
            repository: "repo".into(),
            subjects: vec![AdmissionSubject::for_deployment(&deployment)],
        };
        let error = fetch(
            &endpoint("https://draupnir.example/decide?token=secret"),
            &request,
        )
        .await
        .unwrap_err();
        assert!(error.contains("admission webhook URL"), "{error}");
        assert!(!error.contains("secret"), "URL leaked in {error}");
    }
}
