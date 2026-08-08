//! Signed desired-state contract delivered through the routing repository.

use std::{collections::BTreeMap, path::PathBuf};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::artifact::TargetReference;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAssignment {
    pub schema: u32,
    pub deployment: String,
    pub metadata_url: String,
    pub targets_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
    pub application: TargetReference,
    pub ordered_install_fallback: bool,
    pub provider_set: TargetReference,
    pub release_root: serde_json::Value,
    pub runtime: ManagedRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntime {
    #[serde(default)]
    pub mode: RuntimeMode,
    pub product: String,
    pub channel: String,
    pub install_root: PathBuf,
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretReference>,
    /// Typed values resolved from prerequisite group outputs. Secret values remain references.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, crate::telemetry::OutputValue>,
    pub repository: ManagedRepositoryLimits,
    pub storage: ManagedStorage,
    pub timeouts: ManagedTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub environment: String,
    pub secret: String,
    pub key: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    #[default]
    Managed,
    ProviderManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRepositoryLimits {
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedStorage {
    pub inactive_releases: usize,
    pub inactive_providers: usize,
    pub inactive_supervisors: usize,
    pub inactive_bytes: u64,
    pub inactive_repository_caches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedTimeouts {
    pub check_interval_seconds: u64,
    pub health_grace_seconds: u64,
    pub health_successes: u32,
    pub health_interval_seconds: u64,
    pub refresh_retry_seconds: u64,
    pub confirmation_window_seconds: u64,
    pub supervisor_check_interval_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_hold_seconds: Option<u64>,
}

impl RepositoryAssignment {
    pub const SCHEMA: u32 = 3;

    /// Validate the complete signed contract before a publisher signs it or a node acts on it.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!(
                "unsupported repository assignment schema {}",
                self.schema
            ));
        }
        if self.deployment.is_empty() {
            return Err("repository assignment deployment must not be empty".into());
        }
        for (name, reference) in [
            ("application", &self.application),
            ("provider_set", &self.provider_set),
        ] {
            if !reference.is_valid() {
                return Err(format!("repository assignment {name} reference is invalid"));
            }
        }
        if !self.release_root.is_object() {
            return Err("repository assignment release_root must be a JSON object".into());
        }
        if let Some(report_url) = &self.report_url {
            validate_report_url(report_url)?;
        }
        self.runtime.validate()
    }
}

/// The largest wall-clock interval a signed assignment may carry, and the ceiling every consumer
/// clamps its own waits to.
///
/// Every `*_seconds` field becomes a `Duration` that a consumer adds to an `Instant` or hands to a
/// sleep, and both of those PANIC on overflow, so an unbounded value is a remote crash of every
/// node the assignment reaches — not a merely eccentric policy. Thirty days is far past any
/// legitimate check interval, health grace, drain hold, or retry backoff.
///
/// This is the single definition of that ceiling, on the contract every publisher signs and every
/// consumer ingests: validation here refuses anything above it, and a consumer that additionally
/// clamps (because local state, not just the signed document, can reach its timers) clamps to this
/// same constant rather than to a private copy that could drift from it. It is stated in the unit
/// the wire contract uses — seconds — so there is exactly one spelling of the ceiling and no
/// derived `Duration` twin for a consumer to pick instead.
pub const MAX_INTERVAL_SECONDS: u64 = 30 * 24 * 60 * 60;

impl ManagedRuntime {
    /// Validate signed runtime policy without consulting node-local state.
    pub fn validate(&self) -> Result<(), String> {
        if !crate::path::is_safe_component(&self.product)
            || self.channel.is_empty()
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
            || self.timeouts.supervisor_check_interval_seconds == 0
        {
            return Err("managed runtime limits and timeouts must be non-zero".into());
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
                "timeouts.supervisor_check_interval_seconds",
                self.timeouts.supervisor_check_interval_seconds,
            ),
        ]
        .into_iter()
        .chain(
            self.timeouts
                .drain_hold_seconds
                .map(|hold| ("timeouts.drain_hold_seconds", hold)),
        ) {
            if seconds > MAX_INTERVAL_SECONDS {
                return Err(format!(
                    "{field} ({seconds}) exceeds the {MAX_INTERVAL_SECONDS}s maximum"
                ));
            }
        }
        // The node's report cadence rides on the check loop — it heartbeats at the bottom of it —
        // so every field the supervisor uses as the BASE of its next-check deadline answers to the
        // freshness window every reader ages a report against, not to the generic ceiling above.
        // `check_interval` is that base in steady state and `refresh_retry` is that base after a
        // retryable repository failure; bounding only the first leaves the identical
        // stale-by-construction node one field to the left. Beyond the bound a node's own reports
        // are stale on arrival: drained from the load balancer for part of every cycle, and never
        // counted as settled by the rollout throttle, while being perfectly healthy.
        //
        // What this does NOT cover is the exponential backoff the supervisor multiplies that base
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
        if self.secrets.len() > 64 {
            return Err("managed runtime may declare at most 64 secret references".into());
        }
        crate::telemetry::OutputManifest {
            schema: crate::telemetry::OutputManifest::SCHEMA,
            values: self.inputs.clone(),
        }
        .validate()
        .map_err(|error| format!("managed runtime inputs: {error}"))?;
        if self.mode == RuntimeMode::ProviderManaged && !self.secrets.is_empty() {
            return Err("provider-managed runtime cannot declare application secrets".into());
        }
        let mut environments = std::collections::BTreeSet::new();
        for reference in &self.secrets {
            let valid_environment = !reference.environment.is_empty()
                && reference.environment.len() <= 128
                && reference
                    .environment
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_uppercase()
                            || (index > 0 && byte.is_ascii_digit())
                    })
                && !is_code_injection_variable(&reference.environment);
            if !valid_environment
                || reference.secret.is_empty()
                || reference.secret.len() > 253
                || reference.key.is_empty()
                || reference.key.len() > 253
                || !environments.insert(&reference.environment)
            {
                return Err("managed runtime secret references are invalid or duplicated".into());
            }
        }
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

fn validate_report_url(raw: &str) -> Result<(), String> {
    let url =
        Url::parse(raw).map_err(|error| format!("repository assignment report_url: {error}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "repository assignment report_url must be an absolute HTTP(S) URL without credentials, a query, or a fragment"
                .into(),
        );
    }
    match url.host() {
        Some(Host::Domain(domain)) if !domain.is_empty() => Ok(()),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => Ok(()),
        _ => Err("repository assignment report_url must have a host".into()),
    }
}

fn is_code_injection_variable(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "GLIBC_TUNABLES",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5LIB",
        "PERL5OPT",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "CLASSPATH",
        "PATH",
        "SHELL",
        "BASH_ENV",
        "ENV",
        "IFS",
    ];
    name.starts_with("LD_") || name.starts_with("DYLD_") || EXACT.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::TargetReference;

    fn runtime() -> ManagedRuntime {
        ManagedRuntime {
            mode: RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: BTreeMap::new(),
            repository: ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 30,
            },
            storage: ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
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
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    fn assignment() -> RepositoryAssignment {
        RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "d1".into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            report_url: None,
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

    /// Every `*_seconds` field becomes a `Duration` that a consumer adds to an `Instant` or sleeps
    /// on, and both panic on overflow. A publisher must not be able to emit one that crashes the
    /// fleet, and the bound belongs here — at the contract boundary every consumer already goes
    /// through — rather than as a clamp repeated in each consumer.
    #[test]
    fn every_timeout_is_bounded_from_above() {
        type SetSeconds = fn(&mut ManagedRuntime, u64);
        // The report-cadence fields are absent deliberately: they answer to the tighter,
        // freshness-derived ceiling instead (see below).
        let fields: [(&str, SetSeconds); 6] = [
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
            ("supervisor_check_interval", |r, v| {
                r.timeouts.supervisor_check_interval_seconds = v
            }),
            ("drain_hold", |r, v| r.timeouts.drain_hold_seconds = Some(v)),
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

    /// The node heartbeats at the bottom of its check loop, so whatever the supervisor schedules
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
    fn runtime_mode_defaults_to_managed() {
        let value = serde_json::to_value(runtime()).unwrap();
        let mut object = value.as_object().unwrap().clone();
        object.remove("mode");
        let parsed: ManagedRuntime =
            serde_json::from_value(serde_json::Value::Object(object)).unwrap();
        assert_eq!(parsed.mode, RuntimeMode::Managed);
        assert_eq!(
            serde_json::from_str::<RuntimeMode>("\"provider-managed\"").unwrap(),
            RuntimeMode::ProviderManaged
        );
    }

    #[test]
    fn secret_references_are_strict_and_never_carry_values() {
        let mut value = runtime();
        value.secrets.push(SecretReference {
            environment: "DATABASE_PASSWORD".into(),
            secret: "production-database".into(),
            key: "password".into(),
        });
        value.validate().unwrap();
        let json = serde_json::to_string(&value).unwrap();
        assert!(json.contains("production-database"));
        assert!(!json.contains("secretValue"));

        value.secrets.push(SecretReference {
            environment: "DATABASE_PASSWORD".into(),
            secret: "other".into(),
            key: "password".into(),
        });
        assert!(value.validate().is_err());
        value.secrets[1].environment = "lowercase".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn every_code_injection_environment_is_rejected() {
        for hostile in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "GLIBC_TUNABLES",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "RUBYOPT",
            "PERL5OPT",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "CLASSPATH",
            "PATH",
            "BASH_ENV",
            "IFS",
        ] {
            let mut value = runtime();
            value.secrets.push(SecretReference {
                environment: hostile.into(),
                secret: "attacker".into(),
                key: "payload".into(),
            });
            assert!(value.validate().is_err(), "{hostile}");
        }
        let mut value = runtime();
        value.secrets.push(SecretReference {
            environment: "PATH_TO_LICENSE".into(),
            secret: "licensing".into(),
            key: "path".into(),
        });
        value.validate().unwrap();
    }

    #[test]
    fn assignment_is_strict_and_validates_report_endpoints() {
        let value = assignment();
        value.validate().unwrap();

        let mut offline = value.clone();
        offline.metadata_url = "/opt/update/metadata/".into();
        offline.targets_url = "file:///opt/update/targets/".into();
        offline.validate().unwrap();

        for invalid in [
            "",
            "not-a-url",
            "/relative/only",
            "ftp://cdn/m/",
            "https://",
            "https://user:pass@cdn/report",
        ] {
            let mut candidate = value.clone();
            candidate.report_url = Some(invalid.into());
            assert!(candidate.validate().is_err(), "{invalid:?}");
        }

        assert!(serde_json::from_str::<RepositoryAssignment>(
            r#"{"schema":3,"deployment":"d1","unexpected":true}"#
        )
        .is_err());
        let mut obsolete = value;
        obsolete.schema -= 1;
        assert!(obsolete.validate().is_err());
    }

    #[test]
    fn code_injection_environment_names_are_centrally_rejected() {
        for name in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "NODE_OPTIONS",
        ] {
            assert!(is_code_injection_variable(name), "{name}");
        }
        assert!(!is_code_injection_variable("DATABASE_PASSWORD"));
    }

    #[test]
    fn report_urls_are_bounded_absolute_network_locations() {
        assert!(validate_report_url("https://reports.example.test/base").is_ok());
        for invalid in [
            "file:///tmp/reports",
            "https://user@example.test/",
            "https://example.test/?query",
            "relative/path",
        ] {
            assert!(validate_report_url(invalid).is_err(), "{invalid}");
        }
    }

    /// `CONTROLPLANE_API_CONTRACT.md` publishes `schemas/desired-deployment.schema.json` as the
    /// normative wire contract and points integrators at `schemas/examples`; integrators write
    /// control planes against those files rather than against this crate, and nothing else in the
    /// workspace reads them. Without these checks the two drift into mutually unparseable shapes —
    /// a document the published schema blesses that every agent rejects at
    /// `serde_json::from_slice`, discovered only when a fleet-wide rollout stalls. This is the same
    /// guard `artifact.rs`'s `published_schemas` module applies to the sibling contracts.
    mod published_schema {
        use super::*;
        use serde_json::Value;

        fn read(relative: &str) -> Value {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas")
                .join(relative);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
        }

        /// The field names the Rust type actually serializes, from a value with every optional
        /// field populated.
        fn serialized(value: &impl Serialize) -> Vec<String> {
            let mut keys: Vec<String> = serde_json::to_value(value)
                .expect("serialize")
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect();
            keys.sort();
            keys
        }

        /// A strict object schema must be closed, declare exactly the fields the type serializes,
        /// and require all of them except the ones serde may omit — otherwise a schema-valid
        /// document loses a mandatory field or a type-valid document trips
        /// `additionalProperties`.
        fn assert_object(object: &Value, value: &impl Serialize, optional: &[&str], what: &str) {
            assert_eq!(
                object["additionalProperties"],
                Value::Bool(false),
                "{what} is deny_unknown_fields"
            );
            let mut properties: Vec<String> = object["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{what} properties"))
                .keys()
                .cloned()
                .collect();
            properties.sort();
            assert_eq!(properties, serialized(value), "{what} properties");

            let mut required: Vec<String> = object["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{what} required"))
                .iter()
                .map(|name| name.as_str().expect("required name").to_owned())
                .collect();
            required.sort();
            let mut expected: Vec<String> = properties
                .into_iter()
                .filter(|name| !optional.contains(&name.as_str()))
                .collect();
            expected.sort();
            assert_eq!(required, expected, "{what} required");
        }

        /// A value with every serde-optional field populated, so the schema's property set is
        /// compared against the widest document this type can emit.
        fn complete() -> RepositoryAssignment {
            let mut value = assignment();
            value.report_url = Some("https://reports.example.test/nodes/".into());
            value.runtime.secrets.push(SecretReference {
                environment: "DATABASE_PASSWORD".into(),
                secret: "production-database".into(),
                key: "password".into(),
            });
            value.runtime.inputs.insert(
                "database_host".into(),
                crate::telemetry::OutputValue::String {
                    value: "db.production.internal".into(),
                },
            );
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

            assert_object(&schema, &value, &["report_url"], "assignment");
            assert_eq!(
                schema["properties"]["schema"]["const"],
                Value::from(RepositoryAssignment::SCHEMA)
            );
            for reference in ["application", "provider_set"] {
                assert_eq!(
                    schema["properties"][reference]["$ref"],
                    Value::from("https://updated.dev/schemas/target-reference.schema.json"),
                    "{reference}"
                );
            }
            // `validate` demands a JSON object here, so the schema must not admit a bare string.
            assert_eq!(schema["properties"]["release_root"]["type"], "object");
            assert_eq!(schema["properties"]["runtime"]["$ref"], "#/$defs/runtime");

            let runtime = &schema["$defs"]["runtime"];
            assert_object(
                runtime,
                &value.runtime,
                &["mode", "secrets", "inputs"],
                "runtime",
            );
            assert_eq!(
                runtime["properties"]["secrets"]["maxItems"],
                Value::from(64)
            );
            assert_eq!(
                runtime["properties"]["inputs"]["maxProperties"],
                Value::from(crate::telemetry::OutputManifest::MAX_VALUES)
            );
            assert_object(
                &schema["$defs"]["secret_reference"],
                &value.runtime.secrets[0],
                &[],
                "secret_reference",
            );
            assert_object(
                &schema["$defs"]["repository_limits"],
                &value.runtime.repository,
                &[],
                "repository_limits",
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
            assert_object(
                timeouts,
                &value.runtime.timeouts,
                &["drain_hold_seconds"],
                "timeouts",
            );
            for cadence in ["check_interval_seconds", "refresh_retry_seconds"] {
                assert_eq!(
                    timeouts["properties"][cadence]["maximum"],
                    Value::from(crate::telemetry::MAX_CHECK_INTERVAL_SECONDS),
                    "{cadence}"
                );
            }
            for bounded in [
                "health_grace_seconds",
                "health_interval_seconds",
                "confirmation_window_seconds",
                "supervisor_check_interval_seconds",
                "drain_hold_seconds",
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
