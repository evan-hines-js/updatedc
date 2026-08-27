//! Signed desired-state contract delivered through the routing repository.
//!
//! The three policy structs below — [`ManagedRepositoryLimits`], [`ManagedStorage`],
//! [`ManagedTimeouts`] — are embedded verbatim in the control plane's `UpdateRepository` CRD as
//! well as in this signed document. They derive `JsonSchema` for exactly that reason: the CRD used
//! to declare its own field-for-field twins of all three, which is a second copy of a policy the
//! node acts on, and a second copy drifts. There is one declaration, so there is nothing to drift
//! against.
//!
//! Every name in this document is camelCase, matching the CRD the operator writes and the fields
//! the node reads. A value that crosses that boundary must not change spelling on the way.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::artifact::TargetReference;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryAssignment {
    pub schema: u32,
    pub deployment: String,
    pub metadata_url: String,
    pub targets_url: String,
    pub application: TargetReference,
    pub ordered_install_fallback: bool,
    pub provider_set: TargetReference,
    pub release_root: serde_json::Value,
    pub runtime: ManagedRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedRuntime {
    pub product: String,
    pub channel: String,
    pub install_root: PathBuf,
    /// Opaque descriptor of the atomic file snapshot this node may fetch through an exact,
    /// short-lived S3 capability minted over mTLS.
    #[serde(
        default,
        skip_serializing_if = "crate::dataflow::InputSelection::is_empty"
    )]
    pub inputs: crate::dataflow::InputSelection,
    pub repository: ManagedRepositoryLimits,
    pub storage: ManagedStorage,
    pub timeouts: ManagedTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedRepositoryLimits {
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedStorage {
    pub inactive_releases: usize,
    pub inactive_providers: usize,
    pub inactive_agents: usize,
    pub inactive_bytes: u64,
    pub inactive_repository_caches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedTimeouts {
    pub check_interval_seconds: u64,
    pub health_grace_seconds: u64,
    pub health_successes: u32,
    pub health_interval_seconds: u64,
    pub refresh_retry_seconds: u64,
    pub confirmation_window_seconds: u64,
    pub agent_check_interval_seconds: u64,
}

impl RepositoryAssignment {
    /// The one assignment shape this build reads and writes. Every nested struct denies unknown
    /// fields, and validation requires exact schema equality; no compatibility or alias path exists.
    pub const SCHEMA: u32 = 3;
    /// Whole signed configuration ceiling. The bounded input selection is at most one dataflow
    /// document; the additional MiB covers the pinned TUF root and fixed runtime fields.
    pub const MAX_DOCUMENT_BYTES: usize = crate::dataflow::MAX_DATAFLOW_BODY_BYTES + 1024 * 1024;

    /// Validate the complete signed contract before a publisher signs it or a node acts on it.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!(
                "unsupported repository assignment schema {}",
                self.schema
            ));
        }
        if !crate::identity::is_segment(&self.deployment) {
            return Err("repository assignment deployment identity is invalid".into());
        }
        for (name, location) in [
            ("metadataUrl", self.metadata_url.as_str()),
            ("targetsUrl", self.targets_url.as_str()),
        ] {
            canonical_repository_base(location)
                .map_err(|error| format!("repository assignment {name} is invalid: {error}"))?;
        }
        for (name, reference) in [
            ("application", &self.application),
            ("providerSet", &self.provider_set),
        ] {
            if !reference.is_valid() {
                return Err(format!("repository assignment {name} reference is invalid"));
            }
        }
        if !self.release_root.is_object() {
            return Err("repository assignment releaseRoot must be a JSON object".into());
        }
        self.runtime.validate()?;
        let root_bytes = serde_json::to_vec(&self.release_root)
            .map_err(|error| format!("encoding repository assignment release_root: {error}"))?;
        if root_bytes.len() as u64 > self.runtime.repository.metadata_limit {
            return Err(format!(
                "repository metadata_limit ({}) is smaller than the {}-byte pinned release root",
                self.runtime.repository.metadata_limit,
                root_bytes.len()
            ));
        }
        Ok(())
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        crate::bounded::encode(self, "repository assignment", Self::MAX_DOCUMENT_BYTES)
    }

    /// The bytes to publish and the identity they are known by, together.
    ///
    /// A deployment's identity IS the digest of its published bytes, so producing one without the
    /// other is never correct: the control plane admits, halts and counts nodes by this string,
    /// the object is stored under it, and the node reports back the digest of whatever bytes it
    /// actually verified. If a publisher ever canonicalized differently from whatever derived the
    /// identity, every node would report an identity the planner does not recognise and every
    /// rollout would sit at `Rolling` forever, with the bytes on disk perfectly correct.
    ///
    /// One function because it was previously three steps written out at each publisher — the
    /// Kubernetes control plane and the standalone `server` — and nothing tied the two spellings
    /// together. Validation is inherited from [`Self::to_bounded_json`]: an invalid assignment has
    /// no identity, because it is never published.
    pub fn publication(&self) -> Result<(Vec<u8>, String), String> {
        let bytes = self.to_bounded_json()?;
        let identity = crate::digest::sha256_bytes(&bytes);
        Ok((bytes, identity))
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let assignment: Self =
            crate::bounded::decode(bytes, "repository assignment", Self::MAX_DOCUMENT_BYTES)?;
        assignment.validate()?;
        Ok(assignment)
    }
}

/// Parse and canonicalize the one TUF repository-base grammar carried across the wire.
///
/// Every consumer must go through this function: assignment and enrollment validation, transport
/// construction, and durable repository-lineage identity. That makes equivalent URL spellings
/// (host case, default ports and dot segments) the same repository, and makes it impossible for a
/// parser at the trust boundary to admit a value the transport later interprets differently.
/// Authenticated HTTPS and explicit absolute offline locations are accepted; every result is
/// directory-shaped and carries no credentials or bearer query material.
pub fn canonical_repository_base(value: &str) -> Result<url::Url, String> {
    let url = if PathBuf::from(value).is_absolute() {
        if !value.ends_with(std::path::MAIN_SEPARATOR) {
            return Err("absolute offline directory must end in a path separator".into());
        }
        url::Url::from_directory_path(value)
            .map_err(|()| "absolute offline directory cannot be represented as a file URL")?
    } else {
        #[allow(clippy::disallowed_methods)] // This function is the repository-base authority.
        url::Url::parse(value).map_err(|error| {
            format!("must be an HTTPS/file base URL or absolute directory: {error}")
        })?
    };
    if !crate::endpoint::has_unambiguous_shape(&url, crate::endpoint::QueryPolicy::Forbidden) {
        return Err("must not contain credentials, a query, or a fragment".into());
    }
    if url.cannot_be_a_base() || !url.path().ends_with('/') {
        return Err("must identify a base directory ending with '/'".into());
    }
    match url.scheme() {
        "https" if url.host_str().is_some() => Ok(url),
        "file" if url.host_str().is_none() && url.to_file_path().is_ok() => Ok(url),
        scheme => Err(format!("uses unsupported {scheme} scheme")),
    }
}

/// The largest wall-clock interval a signed assignment may carry, and the ceiling every consumer
/// clamps its own waits to.
///
/// Every `*_seconds` field becomes a `Duration` that a consumer adds to an `Instant` or hands to a
/// sleep, and both of those PANIC on overflow, so an unbounded value is a remote crash of every
/// node the assignment reaches — not a merely eccentric policy. Thirty days is far past any
/// legitimate check interval, health grace, confirmation window, or retry backoff.
///
/// This is the single definition of that ceiling, on the contract every publisher signs and every
/// consumer ingests: validation here refuses anything above it, and a consumer that additionally
/// clamps (because local state, not just the signed document, can reach its timers) clamps to this
/// same constant rather than to a private copy that could drift from it. It is stated in the unit
/// the wire contract uses — seconds — so there is exactly one spelling of the ceiling and no
/// derived `Duration` twin for a consumer to pick instead.
pub const MAX_INTERVAL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Hard resource ceilings for the release repository selected by a signed assignment.
///
/// Metadata is buffered by the TUF client, so an unbounded limit is a fleet-wide memory-exhaustion
/// primitive. Targets stream to disk, but still need a finite contract ceiling so one mistaken or
/// compromised publisher cannot turn every node into an unlimited download sink. The target cap
/// is intentionally above the bundle format's 1 GiB expanded-content ceiling, leaving room for
/// archive framing and non-bundle targets while retaining an actual bound.
pub const MAX_REPOSITORY_METADATA_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_REPOSITORY_TARGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

impl ManagedRuntime {
    /// Validate signed runtime policy without consulting node-local state.
    pub fn validate(&self) -> Result<(), String> {
        if !crate::identity::is_segment(&self.product)
            || !crate::identity::is_segment(&self.channel)
            || !self.install_root.is_absolute()
        {
            return Err("managed runtime product/channel/install_root is invalid".into());
        }
        if self.repository.metadata_limit == 0
            || self.repository.target_limit == 0
            || self.repository.transport_timeout_seconds == 0
            || self.storage.inactive_bytes == 0
            || self.timeouts.check_interval_seconds == 0
            || self.timeouts.health_grace_seconds == 0
            || self.timeouts.health_successes == 0
            || self.timeouts.health_interval_seconds == 0
            || self.timeouts.refresh_retry_seconds == 0
            || self.timeouts.confirmation_window_seconds == 0
            || self.timeouts.agent_check_interval_seconds == 0
        {
            return Err("managed runtime limits and timeouts must be non-zero".into());
        }
        if self.repository.metadata_limit > MAX_REPOSITORY_METADATA_BYTES
            || self.repository.target_limit > MAX_REPOSITORY_TARGET_BYTES
        {
            return Err(format!(
                "managed repository limits exceed the {MAX_REPOSITORY_METADATA_BYTES}-byte metadata or {MAX_REPOSITORY_TARGET_BYTES}-byte target ceiling"
            ));
        }
        for (field, seconds) in [
            (
                "repository.transport_timeout_seconds",
                self.repository.transport_timeout_seconds,
            ),
            (
                "timeouts.health_grace_seconds",
                self.timeouts.health_grace_seconds,
            ),
            (
                "timeouts.health_interval_seconds",
                self.timeouts.health_interval_seconds,
            ),
            (
                "timeouts.confirmation_window_seconds",
                self.timeouts.confirmation_window_seconds,
            ),
            (
                "timeouts.agent_check_interval_seconds",
                self.timeouts.agent_check_interval_seconds,
            ),
        ] {
            if seconds > MAX_INTERVAL_SECONDS {
                return Err(format!(
                    "{field} ({seconds}) exceeds the {MAX_INTERVAL_SECONDS}s maximum"
                ));
            }
        }
        // The node's report cadence rides on the check loop — it heartbeats at the bottom of it —
        // so every field the agent uses as the BASE of its next-check deadline answers to the
        // freshness window every reader ages a report against, not to the generic ceiling above.
        // `check_interval` is that base in steady state and `refresh_retry` is that base after a
        // retryable repository failure; bounding only the first leaves the identical
        // stale-by-construction node one field to the left. Beyond the bound a node's own reports
        // are stale on arrival: drained from the load balancer for part of every cycle, and never
        // counted as settled by the rollout throttle, while being perfectly healthy.
        //
        // What this does NOT cover is the exponential backoff the agent multiplies that base
        // by after repeated failures. A node that cannot refresh its assignment at all cannot show
        // it is running what the control plane assigned, so aging out of "settled" there is the
        // fail-closed direction; a publisher choosing a slow cadence for a perfectly healthy fleet
        // is not.
        for (field, seconds) in [
            (
                "timeouts.check_interval_seconds",
                self.timeouts.check_interval_seconds,
            ),
            (
                "timeouts.refresh_retry_seconds",
                self.timeouts.refresh_retry_seconds,
            ),
        ] {
            if seconds > crate::telemetry::MAX_CHECK_INTERVAL_SECONDS {
                return Err(format!(
                    "{field} ({seconds}) exceeds the {}s maximum that keeps a node's reports inside the shared freshness window",
                    crate::telemetry::MAX_CHECK_INTERVAL_SECONDS
                ));
            }
        }
        self.inputs
            .validate()
            .map_err(|error| format!("managed runtime inputs: {error}"))?;
        let min_grace = u64::from(self.timeouts.health_successes.saturating_sub(1))
            .saturating_mul(self.timeouts.health_interval_seconds);
        if self.timeouts.health_grace_seconds < min_grace {
            return Err(format!(
                "health_grace_seconds ({}) must be >= (health_successes-1)*health_interval_seconds ({min_grace}); otherwise the health streak can never complete within the grace window",
                self.timeouts.health_grace_seconds
            ));
        }
        Ok(())
    }
}

/// Runtime fixtures, for this crate's tests and every downstream crate's.
///
/// [`ManagedRuntime`] is twenty fields of pure policy, and six test modules across four crates each
/// wrote out their own copy of the same nominal value. A field added here then had to be added in
/// six places, and a default changed in one was a default that disagreed with five. Like
/// [`crate::key::testing`], this is deliberately not `#[cfg(test)]`: a `test`-gated item is
/// invisible to other crates, which is what forced the copies in the first place.
pub mod testing {
    use super::{ManagedRepositoryLimits, ManagedRuntime, ManagedStorage, ManagedTimeouts};

    /// Every bound at its floor — the smallest runtime `validate` accepts.
    ///
    /// Distinct from [`runtime`] and used for a distinct purpose: proving the validator admits the
    /// boundary, and giving a planner test cadences it does not have to wait out. Two crates each
    /// wrote their own copy of this, agreeing on all fourteen floors and differing only in an
    /// install root and one limit, which is a copy rather than a variant.
    pub fn minimal_runtime() -> ManagedRuntime {
        ManagedRuntime {
            repository: ManagedRepositoryLimits {
                transport_timeout_seconds: 1,
                ..runtime().repository
            },
            storage: ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_agents: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                agent_check_interval_seconds: 1,
            },
            ..runtime()
        }
    }

    /// The nominal managed runtime every fixture starts from. Callers that care about one field
    /// mutate it; callers that do not are guaranteed to agree with everyone else.
    pub fn runtime() -> ManagedRuntime {
        ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            inputs: crate::dataflow::InputSelection::default(),
            repository: ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 30,
            },
            storage: ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_agents: 2,
                inactive_bytes: 1 << 30,
                inactive_repository_caches: 2,
            },
            timeouts: ManagedTimeouts {
                check_interval_seconds: 15,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                agent_check_interval_seconds: 3600,
            },
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::artifact::TargetReference;

    use testing::runtime;

    fn assignment() -> RepositoryAssignment {
        RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "d1".into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            application: TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: runtime(),
        }
    }

    #[test]
    fn network_repository_locations_are_https_bases_without_embedded_credentials() {
        let mut value = assignment();
        for invalid in [
            "http://objects.example/metadata/",
            "https://user:secret@objects.example/metadata/",
            "https://objects.example/metadata/?token=bearer",
            "https://objects.example/metadata/#fragment",
            "https://objects.example/metadata",
        ] {
            value.metadata_url = invalid.into();
            assert!(value.validate().is_err(), "{invalid:?} must be refused");
        }
        value.metadata_url = "/opt/updated/repository/metadata/".into();
        value.targets_url = "file:///opt/updated/repository/targets/".into();
        assert!(
            value.validate().is_ok(),
            "absolute offline repositories remain supported"
        );
    }

    #[test]
    fn assignment_publishers_and_readers_share_one_document_ceiling() {
        let valid = assignment();
        let bytes = valid.to_bounded_json().unwrap();
        RepositoryAssignment::from_bounded_json(&bytes).unwrap();

        let mut oversized = valid;
        oversized.release_root =
            serde_json::json!({"padding": "x".repeat(RepositoryAssignment::MAX_DOCUMENT_BYTES)});
        assert!(oversized.to_bounded_json().is_err());
        assert!(RepositoryAssignment::from_bounded_json(&vec![
            b' ';
            RepositoryAssignment::MAX_DOCUMENT_BYTES
                + 1
        ])
        .is_err());
    }

    #[test]
    fn every_assignment_identity_uses_the_shared_bounded_segment_grammar() {
        for invalid in [
            "-leading-punctuation".to_string(),
            "nested/channel".to_string(),
            "log\ninjection".to_string(),
            "a".repeat(crate::identity::MAX_SEGMENT_BYTES + 1),
        ] {
            let mut value = assignment();
            value.deployment = invalid.clone();
            assert!(value.validate().is_err(), "deployment {invalid:?}");

            let mut value = assignment();
            value.runtime.product = invalid.clone();
            assert!(value.validate().is_err(), "product {invalid:?}");

            let mut value = assignment();
            value.runtime.channel = invalid.clone();
            assert!(value.validate().is_err(), "channel {invalid:?}");
        }
    }

    /// The identity the control plane admits by, and the digest a node derives from the bytes it
    /// verified, are the same string — and stay the same across a parse.
    ///
    /// This is the whole reason identity and bytes are produced together. The control plane counts,
    /// halts and settles rollouts by this value; the node independently hashes whatever TUF handed
    /// it and reports that. If canonicalization were not a fixed point, every node would report an
    /// identity the planner had never heard of and every rollout would sit at `Rolling` forever
    /// with perfectly correct bytes on disk.
    #[test]
    fn an_assignments_identity_is_the_digest_of_the_bytes_a_node_will_verify() {
        let (bytes, identity) = assignment()
            .publication()
            .expect("a valid assignment publishes");
        assert_eq!(
            identity,
            crate::digest::sha256_bytes(&bytes),
            "the identity must be the digest of exactly the published bytes, which is what the \
             node hashes on the other side"
        );

        // A node parses the bytes; anything re-deriving the identity from the parsed value must
        // land on the same string, or the two sides of the fleet disagree about what is deployed.
        let parsed = RepositoryAssignment::from_bounded_json(&bytes)
            .expect("published bytes are readable by the node");
        let (again, same_identity) = parsed.publication().expect("a parsed assignment publishes");
        assert_eq!(again, bytes, "canonicalization is a fixed point");
        assert_eq!(same_identity, identity);
    }

    #[test]
    fn repository_resource_limits_are_finite_and_can_hold_the_pinned_root() {
        let mut value = assignment();
        value.runtime.repository.metadata_limit = MAX_REPOSITORY_METADATA_BYTES + 1;
        assert!(value.validate().is_err());

        let mut value = assignment();
        value.runtime.repository.target_limit = MAX_REPOSITORY_TARGET_BYTES + 1;
        assert!(value.validate().is_err());

        let mut value = assignment();
        let root_bytes = serde_json::to_vec(&value.release_root).unwrap().len() as u64;
        value.runtime.repository.metadata_limit = root_bytes - 1;
        assert!(value.validate().is_err());
        value.runtime.repository.metadata_limit = root_bytes;
        assert!(value.validate().is_ok());
    }

    /// Every `*_seconds` field becomes a `Duration` that a consumer adds to an `Instant` or sleeps
    /// on, and both panic on overflow. A publisher must not be able to emit one that crashes the
    /// fleet, and the bound belongs here — at the contract boundary every consumer already goes
    /// through — rather than as a clamp repeated in each consumer.
    #[test]
    fn every_timeout_is_bounded_from_above() {
        type SetSeconds = fn(&mut ManagedRuntime, u64);
        // The report-cadence fields are absent deliberately: they answer to the tighter,
        // freshness-derived ceiling instead (see below).
        let fields: [(&str, SetSeconds); 5] = [
            ("transport_timeout", |r, v| {
                r.repository.transport_timeout_seconds = v
            }),
            ("health_grace", |r, v| r.timeouts.health_grace_seconds = v),
            ("health_interval", |r, v| {
                // Keep the lower bound (grace >= (successes-1)*interval) satisfiable so the
                // upper bound is what rejects this, not the pre-existing floor.
                r.timeouts.health_successes = 1;
                r.timeouts.health_interval_seconds = v;
            }),
            ("confirmation_window", |r, v| {
                r.timeouts.confirmation_window_seconds = v
            }),
            ("agent_check_interval", |r, v| {
                r.timeouts.agent_check_interval_seconds = v
            }),
        ];
        for (name, set) in fields {
            let mut at_maximum = runtime();
            set(&mut at_maximum, MAX_INTERVAL_SECONDS);
            assert!(
                at_maximum.validate().is_ok(),
                "{name} at the maximum must remain valid: {:?}",
                at_maximum.validate()
            );
            for hostile in [MAX_INTERVAL_SECONDS + 1, u64::MAX] {
                let mut value = runtime();
                set(&mut value, hostile);
                assert!(
                    value.validate().is_err(),
                    "{name} = {hostile} must be rejected"
                );
                // …and rejected through the whole signed document, not just the runtime.
                let mut signed = assignment();
                set(&mut signed.runtime, hostile);
                assert!(
                    signed.validate().is_err(),
                    "{name} = {hostile} must be rejected by the assignment too"
                );
            }
        }
    }

    /// The node heartbeats at the bottom of its check loop, so whatever the agent schedules
    /// that loop on IS the report cadence and the freshness window every reader enforces is what
    /// bounds it — not the generic 30-day ceiling, under which the perfectly ordinary 60 was
    /// accepted and produced a healthy node that drops out of the load balancer for part of every
    /// single cycle. `refresh_retry` is that schedule after a retryable repository failure, so
    /// leaving it on the generic ceiling reproduces the identical node one field to the left.
    #[test]
    fn every_field_the_report_cadence_rides_on_is_bounded_by_the_freshness_window() {
        use crate::telemetry::{
            MAX_CHECK_INTERVAL_SECONDS, REPORT_CADENCE_JITTER_PERCENT, REPORT_FRESHNESS,
        };

        // Three jittered cadences fit inside the window: two so one lost best-effort report write
        // still leaves the node fresh, and a third for the upload, the store's propagation, and the
        // reader's own poll interval — none of which is free.
        let jittered =
            MAX_CHECK_INTERVAL_SECONDS * u64::from(100 + REPORT_CADENCE_JITTER_PERCENT) / 100 * 3;
        assert!(
            jittered <= REPORT_FRESHNESS.as_secs(),
            "{jittered}s of cadence does not fit in the {}s freshness window",
            REPORT_FRESHNESS.as_secs()
        );

        type SetSeconds = fn(&mut ManagedRuntime, u64);
        let fields: [(&str, SetSeconds); 2] = [
            ("check_interval_seconds", |r, v| {
                r.timeouts.check_interval_seconds = v
            }),
            ("refresh_retry_seconds", |r, v| {
                r.timeouts.refresh_retry_seconds = v
            }),
        ];
        for (name, set) in fields {
            let mut at_maximum = runtime();
            set(&mut at_maximum, MAX_CHECK_INTERVAL_SECONDS);
            at_maximum
                .validate()
                .unwrap_or_else(|error| panic!("{name} at the maximum must remain valid: {error}"));

            for stale in [
                // The value the shipped fixture used to carry: 60s of cadence against a 60s window.
                60,
                MAX_CHECK_INTERVAL_SECONDS + 1,
                MAX_INTERVAL_SECONDS,
                u64::MAX,
            ] {
                let mut value = runtime();
                set(&mut value, stale);
                let error = value
                    .validate()
                    .expect_err("a cadence the freshness window cannot cover must be refused");
                assert!(error.contains(name), "{error}");

                // …and refused through the whole signed document, not just the runtime.
                let mut signed = assignment();
                set(&mut signed.runtime, stale);
                assert!(
                    signed.validate().is_err(),
                    "{name} = {stale} must be rejected by the assignment too"
                );
            }
        }
    }

    #[test]
    fn assignment_is_strict_and_allows_offline_release_repositories() {
        let value = assignment();
        value.validate().unwrap();

        let mut offline = value.clone();
        offline.metadata_url = "/opt/update/metadata/".into();
        offline.targets_url = "file:///opt/update/targets/".into();
        offline.validate().unwrap();

        let mut obsolete = value;
        obsolete.schema -= 1;
        assert!(obsolete.validate().is_err());
    }

    /// [`RepositoryAssignment::SCHEMA`]'s doc rests the whole writer-restraint policy on this
    /// document being closed all the way down: the first generation that emits a new optional field
    /// is refused by every not-yet-upgraded node, so nobody may reach for one.
    ///
    /// The probe this replaces was `{"schema":3,"deployment":"d1","unexpected":true}` — a document
    /// missing eight required fields, which serde rejects for the missing fields whether or not the
    /// struct is closed. Removing `deny_unknown_fields` from any of these structs left it green.
    /// Each probe below is a COMPLETE, valid document with exactly one unknown key inserted, so
    /// the only thing it can fail for is the closedness it claims to check.
    #[test]
    fn the_assignment_and_every_struct_nested_in_it_refuse_an_unknown_field() {
        let value = assignment();
        let document = serde_json::to_value(&value).unwrap();
        serde_json::from_value::<RepositoryAssignment>(document.clone())
            .expect("the probe document parses before anything unknown is added to it");

        // `release_root` and `runtime.inputs` are deliberately open — the signed root is an opaque
        // JSON object and an input is a caller-named value — so neither is probed; every struct
        // this crate declares is.
        for path in [
            "",
            "runtime",
            "runtime/repository",
            "runtime/storage",
            "runtime/timeouts",
        ] {
            let mut probe = document.clone();
            let mut target = &mut probe;
            for key in path.split('/').filter(|key| !key.is_empty()) {
                target = match key.parse::<usize>() {
                    Ok(index) => &mut target[index],
                    Err(_) => &mut target[key],
                };
            }
            target["unexpected"] = serde_json::json!(true);
            assert!(
                serde_json::from_value::<RepositoryAssignment>(probe).is_err(),
                "an unknown field under {path:?} was accepted"
            );
        }
    }

    /// The deployment contract's half of the published-schema conformance check, with
    /// `schemas/examples` as its reference documents. The harness itself — and the rule it enforces
    /// — is [`crate::published_schema`]; this module only names which schema each type must match
    /// and which of its fields serde may omit.
    mod published_schema {
        use super::*;
        use crate::published_schema::{assert_object, read};
        use serde_json::Value;

        /// A value with every serde-optional field populated, so the schema's property set is
        /// compared against the widest document this type can emit.
        fn complete() -> RepositoryAssignment {
            let mut value = assignment();
            value.runtime.inputs = crate::dataflow::InputSelection {
                generation: "a".repeat(64),
                object_sha256: "b".repeat(64),
                files: std::collections::BTreeSet::from(["database_host".into()]),
            };
            value.validate().unwrap();
            value
        }

        #[test]
        fn desired_deployment_schema_matches_the_type() {
            let schema = read("desired-deployment.schema.json");
            assert_eq!(
                schema["$id"],
                Value::from("https://updated.dev/schemas/desired-deployment.schema.json")
            );
            let value = complete();

            assert_object(&schema, &value, &[], "assignment");
            assert_eq!(
                schema["properties"]["schema"]["const"],
                Value::from(RepositoryAssignment::SCHEMA)
            );
            for reference in ["application", "providerSet"] {
                assert_eq!(
                    schema["properties"][reference]["$ref"],
                    Value::from("https://updated.dev/schemas/target-reference.schema.json"),
                    "{reference}"
                );
            }
            // `validate` demands a JSON object here, so the schema must not admit a bare string.
            assert_eq!(schema["properties"]["releaseRoot"]["type"], "object");
            assert_eq!(schema["properties"]["runtime"]["$ref"], "#/$defs/runtime");

            let runtime = &schema["$defs"]["runtime"];
            assert_object(runtime, &value.runtime, &["inputs"], "runtime");
            assert_eq!(
                runtime["properties"]["product"]["maxLength"],
                Value::from(crate::identity::MAX_SEGMENT_BYTES)
            );
            assert_eq!(
                runtime["properties"]["product"]["pattern"],
                Value::from(crate::identity::SEGMENT_PATTERN)
            );
            for field in ["deployment", "channel"] {
                let property = if field == "deployment" {
                    &schema["properties"][field]
                } else {
                    &runtime["properties"][field]
                };
                assert_eq!(
                    property["maxLength"],
                    Value::from(crate::identity::MAX_SEGMENT_BYTES),
                    "{field}"
                );
                // Against the exported grammar, never a literal. This assertion used to carry
                // its own copy of the pattern, so it agreed with a schema that had drifted away
                // from `is_segment` entirely and still passed.
                assert_eq!(
                    property["pattern"],
                    Value::from(crate::identity::SEGMENT_PATTERN),
                    "{field}"
                );
            }
            assert_eq!(
                runtime["properties"]["inputs"]["$ref"],
                Value::from("#/$defs/input_selection")
            );
            let selection = &schema["$defs"]["input_selection"];
            assert_object(selection, &value.runtime.inputs, &[], "input selection");
            assert_eq!(
                selection["properties"]["files"]["maxItems"],
                Value::from(crate::dataflow::FileSnapshot::MAX_FILES)
            );
            assert_eq!(
                selection["properties"]["files"]["items"]["pattern"],
                Value::from(crate::path::SAFE_COMPONENT_PATTERN)
            );
            for digest_field in ["generation", "object_sha256"] {
                assert_eq!(
                    selection["properties"][digest_field]["pattern"],
                    Value::from(foundation::digest::CANONICAL_SHA256_PATTERN),
                    "{digest_field}"
                );
            }
            assert_object(
                &schema["$defs"]["repository_limits"],
                &value.runtime.repository,
                &[],
                "repository_limits",
            );
            assert_eq!(
                schema["$defs"]["repository_limits"]["properties"]["metadataLimit"]["maximum"],
                Value::from(MAX_REPOSITORY_METADATA_BYTES)
            );
            assert_eq!(
                schema["$defs"]["repository_limits"]["properties"]["targetLimit"]["maximum"],
                Value::from(MAX_REPOSITORY_TARGET_BYTES)
            );
            assert_object(
                &schema["$defs"]["storage"],
                &value.runtime.storage,
                &[],
                "storage",
            );

            // The two ceilings `ManagedRuntime::validate` enforces must be the ones the schema
            // publishes, or an integrator sizes a fleet's cadence against a number that fails
            // closed on every node.
            let timeouts = &schema["$defs"]["timeouts"];
            assert_object(timeouts, &value.runtime.timeouts, &[], "timeouts");
            for cadence in ["checkIntervalSeconds", "refreshRetrySeconds"] {
                assert_eq!(
                    timeouts["properties"][cadence]["maximum"],
                    Value::from(crate::telemetry::MAX_CHECK_INTERVAL_SECONDS),
                    "{cadence}"
                );
            }
            for bounded in [
                "healthGraceSeconds",
                "healthIntervalSeconds",
                "confirmationWindowSeconds",
                "agentCheckIntervalSeconds",
            ] {
                assert_eq!(
                    timeouts["properties"][bounded]["maximum"],
                    Value::from(MAX_INTERVAL_SECONDS),
                    "{bounded}"
                );
            }
        }

        /// The published example is the first thing an integrator copies: it must be a document
        /// this build parses and accepts.
        #[test]
        fn the_published_example_parses_and_validates() {
            let example: RepositoryAssignment =
                serde_json::from_value(read("examples/desired-deployment.json")).unwrap();
            example.validate().unwrap();
            assert_eq!(example.schema, RepositoryAssignment::SCHEMA);
        }
    }
}
